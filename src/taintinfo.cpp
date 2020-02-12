/**
 * Kernel taint query utility
 *
 * Copyright (c) Robert Altnoeder 2019, 2020
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <cstddef>
#include <new>
#include <memory>
#include <iostream>
#include <fstream>
#include <stdexcept>

// From the cppdsaext library -- github.com/raltnoeder/cppdsaext
#include <dsaext.h>
#include <integerparse.h>

constexpr std::streamsize BFR_SIZE = 64;
constexpr const char* TAINT_INFO_FILE = "/proc/sys/kernel/tainted";
constexpr char SPACER = '.';
constexpr const char* HEX_CHARS = "0123456789ABCDEF";

constexpr int EXIT_NORM = 0;
constexpr int EXIT_ERR_GENERIC = 1;
constexpr int EXIT_ERR_MEM_ALLOC = 2;

enum class taint_level : uint16_t
{
    INFO    = 0,
    WARN    = 1,
    ALERT   = 2
};

struct taint_info
{
    unsigned int    flag_shift;
    taint_level     level;
    char            flag_off_char;
    char            flag_on_char;
    // off_description can be nullptr if there is no description for a taint flag being unset
    const char*     off_description;
    // on_description must be present (cannot be nullptr)
    const char*     on_description;
};

constexpr taint_info TAINT_FLAGS[] =
{
    {
        0,          taint_level::INFO,  'G',    'P',
        "Only GPL modules were loaded",
        "Proprietary modules were loaded"
    },
    {
        1,          taint_level::WARN,  SPACER, 'F',
        nullptr,
        "Module was force loaded (e.g., insmod -f)"
    },
    {
        2,          taint_level::WARN,  SPACER, 'S',
        nullptr,   "SMP kernel oops on an officially SMP incapable processor"},
    {
        3,          taint_level::ALERT, SPACER, 'R',
        nullptr,   "Module was force unloaded (e.g., rmmod -f)"
    },
    {
        4,          taint_level::ALERT, SPACER, 'M',
        nullptr,   "Processor reported a Machine Check Exception (hardware error)"
    },
    {
        5,          taint_level::ALERT, SPACER, 'B',
        nullptr,   "Bad memory page referenced, or unexpected page flags encountered (possible hardware error)"
    },
    {
        6,          taint_level::WARN,  SPACER, 'U',
        nullptr,   "Taint requested by a userspace application"
    },
    {
        7,          taint_level::ALERT, SPACER, 'D',
        nullptr,   "Kernel OOPS or BUG triggered taint"
    },
    {
        8,          taint_level::WARN,  SPACER, 'A',
        nullptr,   "ACPI Differentiated System Description Table overriden by user"
    },
    {
        9,          taint_level::WARN,  SPACER, 'W',
        nullptr,   "Kernel warning triggered taint"
    },
    {
        10,         taint_level::WARN,  SPACER, 'C',
        nullptr,   "Module from drivers/staging was loaded"
    },
    {
        11,         taint_level::WARN,  SPACER, 'I',
        nullptr,   "Workaround for a bug in platform firmware was applied"
    },
    {
        12,         taint_level::INFO,  SPACER, 'O',
        nullptr,   "Externally-built (out-of-tree) module was loaded"
    },
    {
        13,         taint_level::INFO,  SPACER, 'E',
        nullptr,   "Unsigned module was loaded"
    },
    {
        14,         taint_level::ALERT, SPACER, 'L',
        nullptr,   "Soft lockup occurred"
    },
    {
        15,         taint_level::WARN,  SPACER, 'K',
        nullptr,   "Kernel was live-patched"
    },
    {
        16,         taint_level::WARN,  SPACER, 'X',
        nullptr,   "Auxiliary taint (depending on Linux distribution)"
    },
    {
        17,         taint_level::INFO,  SPACER, 'T',
        nullptr,   "Kernel was built with the struct randomization plugin"
    }
};
constexpr size_t TAINT_FLAGS_ENTRIES = sizeof (TAINT_FLAGS) / sizeof (taint_info);

constexpr const char* F_INFO  = "\x1b[0;32m";
constexpr const char* F_WARN  = "\x1b[1;33m";
constexpr const char* F_ALERT = "\x1b[1;31m";
constexpr const char* F_BOLD  = "\x1b[1m";
constexpr const char* F_RESET = "\x1b[0m";

const std::string PRM_LIST("list");
const std::string PRM_FLAGS("taint=");
const std::string PRM_CURRENT("current");

// @throws std::bad_alloc, dsaext::NumberFormatException
bool taint_load(uint64_t& taint_status);
void taint_analyze(const uint64_t taint_status) noexcept;
void taint_list() noexcept;
void taint_query(const std::string& query_string) noexcept;
void print_syntax(const char* program) noexcept;
static size_t c_str_length(const char* text, size_t max_length) noexcept;
static void print_hex(uint64_t value) noexcept;
static uint64_t get_flag_value(unsigned int taint_shift) noexcept;

int main(const int argc, const char* const argv[])
{
    const char* program = "TaintInfo";
    if (argc >= 1)
    {
        program = argv[0];
    }

    int exit_code = EXIT_ERR_GENERIC;
    try
    {
        if (argc == 2)
        {
            std::string cl_param(argv[1]);
            if (cl_param == PRM_CURRENT)
            {
                uint64_t taint_status = 0;
                exit_code = taint_load(taint_status) ? EXIT_NORM : EXIT_ERR_GENERIC;
                if (exit_code == EXIT_NORM)
                {
                    taint_analyze(taint_status);
                }
            }
            else
            if (cl_param == PRM_LIST)
            {
                taint_list();
                exit_code = EXIT_NORM;
            }
            else
            if (cl_param.find(PRM_FLAGS) == 0)
            {
                taint_query(cl_param.substr(PRM_FLAGS.length(), cl_param.length() - PRM_FLAGS.length()));
                exit_code = EXIT_NORM;
            }
            else
            {
                print_syntax(program);
            }
        }
        else
        {
            print_syntax(program);
        }
    }
    catch (std::bad_alloc&)
    {
        exit_code = EXIT_ERR_MEM_ALLOC;
        std::cerr << F_ALERT << program << ": Out of memory" << F_RESET << std::endl;
    }
    return exit_code;
}

// @throws std::bad_alloc, dsaext::NumberFormatException
bool taint_load(uint64_t& taint_status)
{
    bool rc = false;
    try
    {
        std::ifstream data_in(TAINT_INFO_FILE, std::ios::in | std::ios::binary);
        if (data_in.is_open())
        {
            std::unique_ptr<char[]> data_bfr_mgr(new char[static_cast<size_t> (BFR_SIZE)]);
            char* const data_bfr = data_bfr_mgr.get();

            data_in.get(data_bfr, BFR_SIZE);
            if (!data_in.fail())
            {
                taint_status = dsaext::parse_unsigned_int64_c_str(
                    data_bfr, c_str_length(data_bfr, static_cast<size_t> (BFR_SIZE))
                );
                rc = true;
            }
            else
            {
                std::cerr << F_ALERT << "Cannot read taint status from input file \"" <<
                    TAINT_INFO_FILE << "\": " << "I/O error" << F_RESET << std::endl;
            }
        }
        else
        {
            std::cerr << F_ALERT << "Cannot open input file \"" << TAINT_INFO_FILE << "\"" << F_RESET << std::endl;
        }
    }
    catch (dsaext::NumberFormatException&)
    {
        std::cerr << F_ALERT << "Input file \"" << TAINT_INFO_FILE <<
            "\" contains unparsable data" << F_RESET << std::endl;
    }
    return rc;
}

void taint_query(const std::string& query_input) noexcept
{
    size_t length = query_input.length();
    uint64_t taint_status = 0;
    for (size_t query_idx = 0; query_idx < length; ++query_idx)
    {
        const int upper_char_code = std::toupper(static_cast<const unsigned char> (query_input[query_idx]));
        const char query_flag_char = static_cast<const char> (upper_char_code);
        size_t entry_idx = 0;
        while (entry_idx < TAINT_FLAGS_ENTRIES)
        {
            if (query_flag_char == TAINT_FLAGS[entry_idx].flag_on_char)
            {
                taint_status |= get_flag_value(TAINT_FLAGS[entry_idx].flag_shift);
                break;
            }
            else
            if (TAINT_FLAGS[entry_idx].flag_off_char != SPACER &&
                query_flag_char == TAINT_FLAGS[entry_idx].flag_off_char)
            {
                break;
            }
            ++entry_idx;
        }
        if (entry_idx >= TAINT_FLAGS_ENTRIES)
        {
            std::cerr << F_WARN << "Warning: Unknown taint flag '" << query_flag_char << "' ignored." <<
                F_RESET << std::endl;
        }
    }
    // Check for conflicting taint flags
    for (size_t query_idx = 0; query_idx < length; ++query_idx)
    {
        for (size_t entry_idx = 0; entry_idx < TAINT_FLAGS_ENTRIES; ++entry_idx)
        {
            if (TAINT_FLAGS[entry_idx].flag_off_char != SPACER)
            {
                const int upper_char_code = std::toupper(static_cast<const unsigned char> (query_input[query_idx]));
                const char query_flag_char = static_cast<const char> (upper_char_code);
                uint64_t flag_value = get_flag_value(TAINT_FLAGS[entry_idx].flag_shift);
                if (query_flag_char == TAINT_FLAGS[entry_idx].flag_off_char &&
                    (taint_status & flag_value) == flag_value)
                {
                    std::cerr << F_WARN << "Warning: Conflicting taint flags '" <<
                        TAINT_FLAGS[entry_idx].flag_on_char << "' and '" << TAINT_FLAGS[entry_idx].flag_off_char <<
                        "'" << F_RESET << std::endl;
                    std::cerr << F_WARN << "         Using taint-enabling flag '" <<
                        TAINT_FLAGS[entry_idx].flag_on_char << "'" << F_RESET << std::endl;
                }
            }
        }
    }
    taint_analyze(taint_status);
}

void taint_analyze(const uint64_t taint_status) noexcept
{
    std::cout << F_BOLD << "Taint flags:            " << F_RESET;
    for (size_t idx = 0; idx < TAINT_FLAGS_ENTRIES; ++idx)
    {
        uint64_t flag_value = get_flag_value(TAINT_FLAGS[idx].flag_shift);
        const char* level_format;
        switch (TAINT_FLAGS[idx].level)
        {
            case taint_level::INFO:
                level_format = F_INFO;
                break;
            case taint_level::WARN:
                level_format = F_WARN;
                break;
            case taint_level::ALERT:
                // fall-through
            default:
                level_format = F_ALERT;
                break;
        }
        if ((taint_status & flag_value) == flag_value)
        {
            std::cout << level_format << TAINT_FLAGS[idx].flag_on_char;
        }
        else
        {
            if (TAINT_FLAGS[idx].flag_off_char != SPACER)
            {
                std::cout << level_format;
            }
            std::cout << TAINT_FLAGS[idx].flag_off_char;
        }
        std::cout << F_RESET;
    }
    std::cout << std::endl;
    std::cout << F_BOLD << "Numeric representation: " << F_RESET << taint_status << " / 0x";
    print_hex(taint_status);
    std::cout << std::endl << std::endl;
    for (size_t idx = 0; idx < TAINT_FLAGS_ENTRIES; ++idx)
    {
        uint64_t flag_value = get_flag_value(TAINT_FLAGS[idx].flag_shift);
        const char* level_format;
        switch (TAINT_FLAGS[idx].level)
        {
            case taint_level::INFO:
                level_format = F_INFO;
                break;
            case taint_level::WARN:
                level_format = F_WARN;
                break;
            case taint_level::ALERT:
                // fall-through
            default:
                level_format = F_ALERT;
                break;
        }
        if ((taint_status & flag_value) == flag_value)
        {
            std::cout << "- " << level_format << TAINT_FLAGS[idx].flag_on_char << F_RESET << " " <<
                TAINT_FLAGS[idx].on_description << " (" <<
                get_flag_value(TAINT_FLAGS[idx].flag_shift) << ")" << std::endl;
        }
        else
        if (TAINT_FLAGS[idx].flag_off_char != SPACER && TAINT_FLAGS[idx].off_description != nullptr)
        {
            std::cout << "- " << F_INFO << TAINT_FLAGS[idx].flag_off_char << F_RESET << " " <<
                TAINT_FLAGS[idx].off_description << " (" <<
                get_flag_value(TAINT_FLAGS[idx].flag_shift) << " unset)" << std::endl;
        }
    }
    if (taint_status == 0)
    {
        std::cout << "(Kernel is not tainted)" << std::endl;
    }
    std::cout << std::endl;
}

void taint_list() noexcept
{
    for (size_t idx = 0; idx < TAINT_FLAGS_ENTRIES; ++idx)
    {
        if (TAINT_FLAGS[idx].flag_off_char != SPACER && TAINT_FLAGS[idx].off_description != nullptr)
        {
            std::cout << "- " << TAINT_FLAGS[idx].flag_off_char << ": " <<
                TAINT_FLAGS[idx].off_description << " (" <<
                get_flag_value(TAINT_FLAGS[idx].flag_shift) << " unset)" << std::endl;
        }
        std::cout << "- " << TAINT_FLAGS[idx].flag_on_char << ": " <<
            TAINT_FLAGS[idx].on_description << " (" <<
            get_flag_value(TAINT_FLAGS[idx].flag_shift) << ")" << std::endl;
    }
}

void print_syntax(const char* const program) noexcept
{
    std::cout << "Syntax: " << program << " { current | list | taint=<flags> }\n";
    std::cout << "        current      Display information about the current taint status of the running kernel\n";
    std::cout << "        list         List all known taint flags and their descriptions\n";
    std::cout << "        taint=flags  Display information about the specified taint flags\n";
    std::cout << std::endl;
}

static size_t c_str_length(const char* const text, const size_t max_length) noexcept
{
    size_t length = 0;
    while (length < max_length && text[length] != '\0')
    {
        ++length;
    }
    return length;
}

static void print_hex(const uint64_t value) noexcept
{
    uint64_t remainder = value;
    const size_t max_counter = 16;
    for (size_t counter = 0; counter < max_counter; ++counter)
    {
        const uint8_t hex_digit = static_cast<uint8_t> (remainder >> 60);
        std::cout << HEX_CHARS[hex_digit];
        remainder <<= 4;
    }
}

static uint64_t get_flag_value(const unsigned int flag_shift) noexcept
{
    return static_cast<uint64_t> (1) << flag_shift;
}

