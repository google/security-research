#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -e
source testing.sh

verify_output ../zentool print ../data/cpu00830F10_ver0830101C_2019-05-08_8DC96EF2.bin
verify_output ../zentool print ../data/cpu00830F10_ver08301025_2019-07-11_337F26F5.bin
verify_output ../zentool print ../data/cpu00830F10_ver08301034_2019-10-24_1D1A2F9D.bin
verify_output ../zentool print ../data/cpu00830F10_ver08301038_2019-12-24_29A93343.bin
verify_output ../zentool print ../data/cpu00830F10_ver08301039_2020-02-07_9A4141DB.bin
verify_output ../zentool print ../data/cpu00830F10_ver0830104D_2020-07-28_22CD4D3D.bin
verify_output ../zentool print ../data/cpu00830F10_ver08301052_2021-11-11_490C60F8.bin
verify_output ../zentool print ../data/cpu00830F10_ver08301055_2022-02-15_65A2763D.bin
verify_output ../zentool print ../data/cpu00830F10_ver08301072_2022-02-15_B2AE2EBD.bin
verify_output ../zentool print ../data/cpu00830F10_ver0830107A_2023-05-17_D7882D6C.bin
verify_output ../zentool print ../data/cpu00830F10_ver0830107B_2023-08-16_8F6C1421.bin
verify_output ../zentool print ../data/cpu00830F10_ver0830107C_2023-12-18_6CEA85AD.bin
verify_output ../zentool print ../data/cpu00860F01_ver08600102_2019-11-17_444C1A3D.bin
verify_output ../zentool print ../data/cpu00860F01_ver08600103_2020-01-27_4F9C2C4C.bin
verify_output ../zentool print ../data/cpu00860F01_ver08600104_2020-05-26_6D414322.bin
verify_output ../zentool print ../data/cpu00860F01_ver08600106_2020-06-19_ACE2511D.bin
verify_output ../zentool print ../data/cpu00860F01_ver08600109_2022-03-28_DA3355E7.bin
verify_output ../zentool print ../data/cpu00860F01_ver0860010C_2023-10-07_3D4A6C3D.bin
verify_output ../zentool print ../data/cpu00860F81_ver08608103_2020-07-02_19A74DF3.bin
verify_output ../zentool print ../data/cpu00A40F00_ver0A400016_2021-03-30_B8EFF68B.bin
verify_output ../zentool print ../data/cpu00A40F40_ver0A404002_2021-04-08_35A6F7C3.bin
verify_output ../zentool print ../data/cpu00A40F41_ver0A404101_2021-10-18_17FBEE6D.bin
verify_output ../zentool print ../data/cpu00A40F41_ver0A404102_2021-10-18_78BCFB87.bin
verify_output ../zentool print ../data/cpu00A40F41_ver0A404105_2023-07-07_3657C9F8.bin
verify_output ../zentool print ../data/cpu00A50F00_ver0A500008_2020-07-10_BE10AB67.bin
verify_output ../zentool print ../data/cpu00A50F00_ver0A50000B_2020-08-21_7F768F82.bin
verify_output ../zentool print ../data/cpu00A50F00_ver0A50000C_2020-12-08_A47A9DC7.bin
verify_output ../zentool print ../data/cpu00A50F00_ver0A50000D_2021-10-14_DDD9A4AA.bin
verify_output ../zentool print ../data/cpu00A50F00_ver0A50000F_2023-07-07_72B4B8C6.bin
verify_output ../zentool print ../data/cpu00A70F00_ver0A700003_2022-05-17_3D81C7E0.bin
verify_output ../zentool print ../data/cpu00A70F40_ver0A704001_2022-07-21_5BD9C29C.bin
verify_output ../zentool print ../data/cpu00A70F41_ver0A704103_2023-04-17_8FC1AB4C.bin
verify_output ../zentool print ../data/cpu00A70F41_ver0A704104_2023-07-13_3C8FAC0D.bin
verify_output ../zentool print ../data/cpu00A70F42_ver0A704201_2022-10-03_EF03AE09.bin
verify_output ../zentool print ../data/cpu00A70F42_ver0A704202_2023-07-13_D616C48D.bin
verify_output ../zentool print ../data/cpu00A70F52_ver0A705203_2023-07-13_4B8DA9D5.bin
verify_output ../zentool print ../data/cpu00A70F52_ver0A705205_2024-01-12_753FB641.bin
verify_output ../zentool print ../data/cpu00A70F80_ver0A708000_2022-10-04_8893BFB8.bin
verify_output ../zentool print ../data/cpu00A70F80_ver0A708004_2023-07-13_BC63AEE6.bin
verify_output ../zentool print ../data/cpu00A70F80_ver0A708006_2024-01-12_AD8FB607.bin
verify_output ../zentool print ../data/cpu00A70FC0_ver0A70C002_2023-07-13_0A12A8E0.bin

