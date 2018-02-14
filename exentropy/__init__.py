import struct, math
from elftools.elf.elffile import ELFFile
from enum import Enum
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.sections import NoteSection, SymbolTableSection
import json

from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_ver_flags, describe_note
)

from elftools.elf.gnuversions import (
    GNUVerSymSection, GNUVerDefSection,
    GNUVerNeedSection,
)


class ElfInfo(object):
    def __init__(self, file, verbose=False):
        self.elffile = ELFFile(file)
        self._versioninfo = None
        self.data = {}
        self._verbose = verbose

    def __str__(self):
        return json.dumps(self.data)

    def _emitline(self, s=''):
        if self._verbose:
            print(str(s).rstrip() + '\n')

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
        """ Search and initialize informations about version related sections
            and the kind of versioning used (GNU or Solaris).
        """
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
        """ Display the symbol tables contained in the file
        """
        self._init_versioninfo()

        symbol_tables = [s for s in self.elffile.iter_sections() if isinstance(s, SymbolTableSection)]

        if not symbol_tables and self.elffile.num_sections() == 0:
            self._emitline('')
            self._emitline('Dynamic symbol information is not available for displaying symbols.')

        imports = set()
        jexports = set()
        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                self._emitline("\nSymbol table '%s' has a sh_entsize of zero!" % (
                    section.name))
                continue

            self._emitline("\nSymbol table '%s' contains %s entries:" % (
                section.name, section.num_symbols()))

            if self.elffile.elfclass == 32:
                self._emitline('   Num:    Value  Size Type    Bind   Vis      Ndx Name')
            else: # 64
                self._emitline('   Num:    Value          Size Type    Bind   Vis      Ndx Name')

            for nsym, symbol in enumerate(section.iter_symbols()):
                version_info = ''
                # readelf doesn't display version info for Solaris versioning
                if (section['sh_type'] == 'SHT_DYNSYM' and
                        self._versioninfo['type'] == 'GNU'):
                    version = self._symbol_version(nsym)
                    if (version is not None and version['name'] != symbol.name and
                            version['index'] not in ('VER_NDX_LOCAL',
                                                     'VER_NDX_GLOBAL')):
                        if version['filename']:
                            # external symbol
                            version_info = '@%(name)s (%(index)i)' % version
                        else:
                            # internal symbol
                            if version['hidden']:
                                version_info = '@%(name)s' % version
                            else:
                                version_info = '@@%(name)s' % version

                # symbol names are truncated to 25 chars, similarly to readelf
                self._emitline('%6d: %s %5d %-7s %-6s %-7s %4s %s%s' % (
                    nsym,
                    self._format_hex(
                        symbol['st_value'], fullhex=True, lead0x=False),
                    symbol['st_size'],
                    describe_symbol_type(symbol['st_info']['type']),
                    describe_symbol_bind(symbol['st_info']['bind']),
                    describe_symbol_visibility(symbol['st_other']['visibility']),
                    describe_symbol_shndx(symbol['st_shndx']),
                    symbol.name,
                    version_info))

                t = describe_symbol_type(symbol['st_info']['type'])
                if t == "FUNC":
                    x = describe_symbol_shndx(symbol['st_shndx'])
                    if x == "UND":
                        imports.add(str(symbol.name))
                    try:
                        x = int(x)
                        if symbol.name.startswith("Java_"):
                            jexports.add(str(symbol.name))
                    except ValueError:
                        pass
        self.data["imports"] = list(imports)
        self.data["jexports"] = list(jexports)


    def _symbol_version(self, nsym):
        """ Return a dict containing information on the
                   or None if no version information is available
        """
        self._init_versioninfo()

        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self._versioninfo['versym'] or
                nsym >= self._versioninfo['versym'].num_symbols()):
            return None

        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self._versioninfo['type'] == 'GNU':
                # In GNU versioning mode, the highest bit is used to
                # store wether the symbol is hidden or not
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self._versioninfo['verdef'] and
                    index <= self._versioninfo['verdef'].num_versions()):
                _, verdaux_iter = \
                        self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = \
                        self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return

    def display_dynamic_tags(self):
        for section in self.elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            shlib = set()
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    self._emitline('Shared library: [%s]' % tag.needed)
                    shlib.add(tag.needed)
            self.data["shlib"] = list(shlib)


    def compute_entropy(self, text):
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


    def print_infos(self):

            elf = self.elffile
            self.display_dynamic_tags()

            sections = []
            for section in elf.iter_sections():
                if section.name != '':
                    entropy = self.compute_entropy(section.data())
                    self._emitline('{name} {size} {flags} {ent}'.format(
                        name=section.name,
                        size=section.header['sh_size'],
                        flags=section.header['sh_flags'],
                        ent=entropy
                    ))
                    s = {"name": section.name, "size": int(section.header['sh_size']),
                         "flags": int(section.header['sh_flags']), "entro": float(entropy)}
                    sections.append(s)
            self.data["sections"] = sections

            segments = []
            for segment in elf.iter_segments():
                entropy = self.compute_entropy(segment.data())
                self._emitline('{name} {size} {flags} {ent}'.format(
                    name=segment.header["p_type"][3:],  # remove "PT_"
                    size=segment.header["p_memsz"],
                    flags=segment.header["p_flags"],
                    ent=entropy))
                s = {"name": segment.header["p_type"], "size": int(segment.header["p_memsz"]),
                         "flags": int(segment.header['p_flags']), "entro": float(entropy)}
                segments.append(s)
            self.data["segments"] = segments

if __name__ == "__main__":
    filepath = "/home/simo/Dropbox/AndroidCTF/boeing/libnative-lib.so"
    #filepath = "/home/simo/AAndroMalware/Android_apks/DREBIX_DATASET/libandroidterm.so"
    #r2 = r2pipe.open(filepath)
    #r2.cmd('aa')
    #print(r2.cmdj("afl"))

    with open(filepath, 'rb') as file:
        t = ElfInfo(file)
        t.display_symbol_tables()
        t.print_infos()
        print(t)