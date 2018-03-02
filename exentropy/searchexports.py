import json
import argparse
import math
import os.path
import struct
import sys
from elftools.elf.descriptions import (describe_symbol_type, describe_symbol_shndx)
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import (GNUVerSymSection, GNUVerDefSection, GNUVerNeedSection)
from elftools.elf.sections import SymbolTableSection


class ElfInfo(object):
    def __init__(self, file, verbose=False):
        self.elffile = ELFFile(file)
        self._versioninfo = None
        self.data = {}
        self.data["arch"] = self.elffile.elfclass
        self._verbose = verbose

    def __str__(self):
        return json.dumps(self.data)

    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True, alternate=False):
        if alternate:
            if addr == 0:
                lead0x = False
            else:
                lead0x = True
                fieldsize -= 2
        s = '0x' if lead0x else ''
        if fullhex:
            fieldsize = 8 if self.elffile.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr

    def _init_versioninfo(self):
        if self._versioninfo is not None:
            return
        self._versioninfo = {'versym': None, 'verdef': None, 'verneed': None, 'type': None}
        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._versioninfo['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                self._versioninfo['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                self._versioninfo['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        self._versioninfo['type'] = 'GNU'
                        break
        if not self._versioninfo['type'] and (
                self._versioninfo['verneed'] or self._versioninfo['verdef']):
            self._versioninfo['type'] = 'Solaris'

    def display_symbol_tables(self):
        self._init_versioninfo()
        symbol_tables = [s for s in self.elffile.iter_sections() if isinstance(s, SymbolTableSection)]
        imports = set()
        exports = set()
        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue
            if section['sh_entsize'] == 0:
                # print("\nSymbol table '%s' has a sh_entsize of zero!" % (section.name))
                continue
            for nsym, symbol in enumerate(section.iter_symbols()):
                sym_type = describe_symbol_type(symbol['st_info']['type'])
                if sym_type == "FUNC":
                    desc = describe_symbol_shndx(symbol['st_shndx'])
                    if desc == "UND":
                        imports.add(str(symbol.name))
                    try:
                        exports.add(str(symbol.name))
                    except ValueError:
                        pass
        self.data["imports"] = list(imports)
        self.data["exports"] = list(exports)

    def _symbol_version(self, nsym):
        self._init_versioninfo()
        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))
        if (not self._versioninfo['versym'] or nsym >= self._versioninfo['versym'].num_symbols()):
            return None
        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)
            if self._versioninfo['type'] == 'GNU':
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True
            if self._versioninfo['verdef'] and index <= self._versioninfo['verdef'].num_versions():
                verdaux_iter = self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name
        symbol_version['index'] = index

    def collect_sharedlib(self):
        for section in self.elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            shlib = set()
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    # print('Shared library: [%s]' % tag.needed)
                    shlib.add(tag.needed)
            self.data["shlib"] = list(shlib)

    def collect_sections_segments(self):
        elf = self.elffile
        sections = []
        for section in elf.iter_sections():
            if section.name != '':
                entropy = self.compute_entropy(section.data())
                # print('{} {} {} {}'.format(section.name, section.header['sh_size'], section.header['sh_flags'], entropy))
                s = {"name": section.name, "size": int(section.header['sh_size']),
                     "flags": int(section.header['sh_flags']), "entro": float(entropy)}
                sections.append(s)
        self.data["sections"] = sections
        segments = []
        for segment in elf.iter_segments():
            entropy = self.compute_entropy(segment.data())
            # print('{} {} {} {}'.format(segment.header["p_type"], segment.header["p_memsz"], segment.header["p_flags"], entropy))
            s = {"name": segment.header["p_type"], "size": int(segment.header["p_memsz"]),
                     "flags": int(segment.header['p_flags']), "entro": float(entropy)}
            segments.append(s)
        self.data["segments"] = segments

    @staticmethod
    def compute_entropy(text):
        map_of_bytes = dict()
        entropy = 0
        for byte in text:
            i = struct.unpack('h', byte + "\x00")[0]
            if not map_of_bytes.has_key(i):
                map_of_bytes[i] = 1
            else:
                map_of_bytes[i] += 1
        for key in map_of_bytes:
            p = float(map_of_bytes[key]) / float(len(text))
            if p > 0:
                entropy -= p * math.log(p, 2)
        # We obtain an entropy value in range 0, 8
        return entropy

    def get_infos(self):
        self.collect_sections_segments()
        self.collect_sharedlib()
        self.display_symbol_tables()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract imports from all ELF files in directory')
    parser.add_argument('folder', metavar='dir', help='the folder to be analyzed')
    parser.add_argument('output_file', metavar='file', help='where to write results')
    args = parser.parse_args()
    result_set = set()
    DIR = args.folder
    OUT_PATH = args.output_file
    if not os.path.isdir(DIR):
        print(DIR + ' does not exists or it is not a folder.')
        sys.exit()

    for dirpath, dir_names, file_names in os.walk(args.folder):
        for f in file_names:
            file_path = os.path.join(dirpath, f)
            try:
                elf = ElfInfo(open(file_path, 'rb'))
                elf.display_symbol_tables()
                for i in elf.data['exports']:
                    result_set.add(i)
            except Exception as e:
                print('Problem with file: ', file_path, '\nError is: ', e)

    f = open(OUT_PATH, 'w')
    for i in result_set:
        f.write("{}\n".format(i))
    f.close()
