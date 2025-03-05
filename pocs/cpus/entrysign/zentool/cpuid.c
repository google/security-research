/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "parse.h"
#include "options.h"

const char * zen_cpuid_lookup(uint8_t extfam, uint8_t model, uint8_t extmodel, uint8_t stepping)
{
    const char *cpuname = "Unknown";

    (void) stepping;

    if (extfam == 8) {
        cpuname = "Zen/Zen+/Zen2";

        dbgmsg("this is %s, looking for more specific name", cpuname);

        if (model == 0 && extmodel ==  0) cpuname = "AMD EPYC (1st Gen) (Snowy Owl, Naples, Summit Ridge)";
        if (model == 0 && extmodel ==  1) cpuname = "AMD Ryzen (Banded Kestrel, Great Horned Owl, Raven Ridge)";
        if (model == 0 && extmodel ==  2) cpuname = "AMD Ryzen (Dali)";
        if (model == 0 && extmodel ==  3) cpuname = "AMD EPYC (2nd Gen) (Castle Peak/Rome)";
        if (model == 0 && extmodel ==  6) cpuname = "AMD Ryzen (Grey Hawk, Renoir)";
        if (model == 0 && extmodel ==  7) cpuname = "AMD Ryzen (Matisse)";
        if (model == 0 && extmodel ==  9) cpuname = "AMD Ryzen (Van Gogh)";
        if (model == 0 && extmodel == 10) cpuname = "AMD Ryzen (Mendocino)";
        if (model == 8 && extmodel ==  0) cpuname = "AMD Ryzen (Colfax, Pinnacle Ridge)";
        if (model == 8 && extmodel ==  1) cpuname = "AMD Ryzen (Zen+, Picasso)";
        if (model == 8 && extmodel ==  6) cpuname = "AMD Ryzen (Zen2, Lucienne)";
        if (model == 8 && extmodel ==  9) cpuname = "AMD Ryzen (Mero)";
    }

    if (extfam == 10) {
        cpuname = "Zen3/Zen4";

        dbgmsg("this is %s, looking for more specific name", cpuname);

        if (model ==  0 && extmodel ==  0) cpuname = "AMD EPYC (3rd Gen) (Milan)";
        if (model ==  0 && extmodel ==  1) cpuname = "AMD EPYC (4th Gen) (Genoa)";
        if (model ==  0 && extmodel ==  2) cpuname = "AMD Ryzen (Vermeer)";
        if (model ==  0 && extmodel ==  3) cpuname = "AMD Ryzen (Badami)";
        if (model ==  0 && extmodel ==  4) cpuname = "AMD Ryzen (Zen3+, Rembrandt)";
        if (model ==  0 && extmodel ==  5) cpuname = "AMD Ryzen (Zen3, Cezanne/Barcelo)";
        if (model ==  0 && extmodel ==  6) cpuname = "AMD Ryzen (Raphael)";
        if (model ==  0 && extmodel ==  7) cpuname = "AMD Ryzen (Zen4, Phoenix)";
        if (model ==  0 && extmodel == 10) cpuname = "AMD EPYC (4th Gen) (Bergamo/Siena)";
        if (model ==  8 && extmodel ==  0) cpuname = "AMD Ryzen (Chagall)";
        if (model ==  8 && extmodel ==  1) cpuname = "AMD Ryzen (Storm Peak)";
        if (model ==  8 && extmodel ==  7) cpuname = "AMD Ryzen (Phoenix 2)";
        if (model == 12 && extmodel ==  7) cpuname = "AMD Ryzen (Hawk Point)";
    }

    if (extfam == 11) {
        cpuname = "Zen5";
    }

    return cpuname;
}
