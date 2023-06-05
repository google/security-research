---
title: 'Jose4j: Chosen Ciphertext Attack in Jose4j'
severity: Moderate
ghsa_id: GHSA-jgvc-jfgh-rjvv
cve_id: null
weaknesses: []
products:
- ecosystem: jose4j
  package_name: jose4j
  affected_versions: Refer to Further Analysis
  patched_versions: ''
cvss: null
credits:
- github_user_id: bleichen
  name: Daniel Bleichenbacher
  avatar: https://avatars.githubusercontent.com/u/25984990?s=40&v=4
---

### Summary
RSA1_5 in jose4j is susceptible to chosen ciphertext attacks. The
attack allows to decrypt RSA1_5 or RSA_OAEP encrypted ciphertexts. It may
be feasible to sign with affected keys.

### Severity
Moderate - exploiting this ciphertext attack could result in the ability to decrypt RSA1_5 or RSA_OAEP encrypted ciphertexts.

### Proof of Concept
A test case that can reproduce the padding oracle uses the following private key:

```
{
        "kty": "RSA",
        "alg": "RSA1_5",
        "use": "enc",
        "n": "w2A4cbwOAK4ATnwXkGWereqv9dkEcgAGHc9g-cjo1HFeilYirvfD2Un2vQxW_6g2OKRPmmo46vMZFMYv_V57174j411y-NQlZGb7iFqMQADzo60VZ7vpvAX_NuxNGxYR-N2cBgvgqDiGAoO9ouNdhuHhxipTjGVfrPUpxmJtNPZpxsgxQWSpYCYMl304DD_5wWrnumNNIKOaVsAYmjFPV_wqxFCHbitPd1BG9SwXPk7wAHtXT6rYaUImS_OKaHkTO1OO0PNhd3-wJRNMCh_EGUwAghfWgFyAd20pQLZamamxgHvfL4-0hwuzndhHt0ye-gRVTtXDFEwABB--zwvlCw",
        "e": "AQAB",
        "kid": "rsa1_5",
        "d": "EjMvbuDeyQ9sdeM3arscqgTXuWYq9Netui8sUHh3v_qDnQ1jE7t-4gny0y-IFy67RlGAHNlSTgixSG8h309i5_kNbMuyvx08EntJaS1OLVQpXhDskoo9vscsPBiNIj3PFMjIFQQcPG9vhGJzUu4tMzhtiME-oTB8VidMae-XTryPvozTu4rgfb4U7uauvLqESLz3A5xtzPnwNwqXAIlrdxU-MT_iln08on_QIF8afWUqCbsWWjEck_QDKLVpzh8VV9kkEVWwYfCFhHBwS-fgGJJTE3gK4HwOokydMtH95Dzj47MA2pLe600l7ioyGSPltcv967NtOpxMPM5ro751KQ",
        "p": "-F1u3NAMWPu1TIuvIywIjh5fuiA3AVKLgS6Fw_hAi3M9c3T7E1zNJZuHgQExJEu06ZPfzye9m7taDzh-Vw4VGDED_MZedsE2jEsWa9EKeq3bZVf5j81FLCHH8BicFqrPjvoVUC35wrl9SGJzaOa7KXxD2jW22umYjJS_kcopvf0",
        "q": "yWHG7jHqvfqT8gfhIlxpMbeJ02FrWIkgJC-zOJ26wXC6oxPeqhqEO7ulGqZPngNDdSGgWcQ7noGEU8O4MA9V3yhl91TFZy8unox0sGe0jDMwtxm3saXtTsjTE7FBxzcR0PubfyGiS0fJqQcj8oJSWzZPkUshzZ8rF3jTLc8UWac",
        "dp": "Va9WWhPkzqY4TCo8x_OfF_jeqcYHdAtYWb8FIzD4g6PEZZrMLEft9rWLsDQLEiyUQ6lio4NgZOPkFDA3Vi1jla8DYyfE20-ZVBlrqNK7vMtST8pkLPpyjOEyq2CyKRfQ99DLnZfe_RElad2dV2mS1KMsfZHeffPtT0LaPJ_0erk",
        "dq": "M8rA1cviun9yg0HBhgvMRiwU91dLu1Zw_L2D02DFgjCS35QhpQ_yyEYHPWZefZ4LQFmoms2cI7TdqolgmoOnKyCBsO2NY29AByjKbgAN8CzOL5kepEKvWJ7PonXpG-ou29eJ81VcHw5Ub_NVLG6V7b13E0AGbpKsC3pYnaRvcGs",
        "qi": "8zIqISvddJYC93hP0sKkdHuVd-Mes_gsbi8xqSFYGqc-wSU12KjzHnZmBuJl_VTGy9CO9W4K2gejr588a3Ozf9U5hx9qCVkV0_ttxHcTRem5sFPe9z-HkQE5IMW3SdmL1sEcvkzD7z8QhcHRpp5aMptfuwnxBPY8U449_iNgXd4"
      },
```
jose4j has distinguishable behvaior for the following test cases:

The first ciphertext below contains an invalid PKCS #1 padding.  Because of hte invalid padding a random AES key is generated during decryption.  This leads to an authentication error.

```
"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.ksmeZ6dBbP0UfDEaLXlqPl2XDaAA29kGlKtDb89x-4xN5-A6bx2umI_ToHK2GadzxUOgKROCACYb6rmKsqsQCOZaBsnq_4mDII1W0pja7Lz4zTnr7R3O4kALg4zXqG-gSlcDA7k1NgkpMDS15PjMmADqyqxbxQsXdfjstN324iqdvYGh6NsckkfTSWxDVAqiSR9fW8PsIbo3uSMokNaC-f64CDWIB9AsCxhF-3mnFbxXNxw7JE0upOgG4enQ8kZkwi_v54HBqAau1YNW7gPhFV8ElTQ71J6aHB3dja23lbWdaJmrK6PJE7gEeZmUbFkSYmuyzRUS-NGfXA23fYv5JQ.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEHiaqhiQ"
```

The second ciphertext below ontains valid PKCS #1 padding, but the size of the encoded key is incorrect.  Because of this, trying to dcrypt the symmetric part of the ciphertext immediately fails with org.jose4j.lang.JoseException: Invalid key for AES/GCM/NoPadding.

```
"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.oyVTmkyoChxFtyCtiKhv8OpBJcV6C6s_gMFSSRJBNStpdHPzq2YmroTfXGj1J1plFG4BBQwIZtdt6rIS6YkCvTLGqP1hds9CAO1a_bgRyoAVuOVvH2vmz5U2r74_SRbAzD35M7yZ_tSnnEdMFlHMFbf5uNwmgArrtPgh0V5OLn5i4XIc154FLTiQlvAEhUxiPuYBkm_1GBiYEH4JjP2RKXAUx_TxAVwPsOfIPAVrO0Ev_nvdtVLCE-uOn8WQbxh4wwOztaXOV1HIaPrl7HN-YtDOA840QUHm97ZZLAPRgLzGlkMI0ZS8QkYdb9_FT3KMbNu60nBKEniv2uhBdIhM9g.46AsIpPgnJCLH0Xm.u2rG.LyEHEGCWM8CXDEEHiaqhiQ"
```

A correct implementation would not have distinguishable behavior.  A test case for the missing algorithm checks uses the key:

```
{
        "alg": "RSA-OAEP",
        "use": "enc",
        "n": "kqGboBfAWttWPCA-0cGRgsY6SaYoIARt0B_PkaEcIq9HPYNdu9n6UuWHuuTHrjF_ZoQW97r5HaAorNvrMEGTGdxCHZdEtkHvNVVmrtxTBLiQCbCozXhFoIrVcr3qUBrdGnNn_M3jJi7Wg7p_-x62nS5gNG875oyheRkutHsQXikFZwsN3q_TsPNOVlCiHy8mxzaFTUQGm-X8UYexFyAivlDSjgDJLAZSWfxd7k9Gxuwa3AUfQqQcVcegmgKGCaErQ3qQbh1x7WB6iopE3_-GZ8HMAVtR9AmrVscqYsnjhaCehfAI0iKKs8zXr8tISc0ORbaalrkk03H1ZrsEnDKEWQ",
        "e": "AQAB",
        "d": "YsfIRYN6rDqSz5KRf1E9q7HK1o6-_UK-j7S-asb0Y1FdVs1GuiRQhMPoOjmhY3Io93EI3_7vj8uzWzAUMsAaTxOY3sJnIbktYuqTcD0xGD8VmdGPBkx963db8B6M2UYfqZARf7dbzP9EuB1N1miMcTsqyGgfHGOk7CXQ1vkIv8Uww38KMtEdJ3iB8r-f3qcu-UJjE7Egw9CxKOMjArOXxZEr4VnoIXrImrcTxBfjdY8GbzXGATiPQLur5GT99ZDW78falsir-b5Ean6HNyOeuaJuceT-yjgCXn57Rd3oIHD94CrjNtjBusoLdjbr489L8K9ksCh1gynzLGkeeWgVGQ",
        "p": "0xalbl1PJbSBGD4XOjIYJLwMYyHMiM06SBauMGzBfCask5DN5jH68Kw1yPS4wkLpx4ltGLuy0X5mMaZzrSOkBGb27-NizBgB2-L279XotznWeh2jbF05Kqzkoz3VaX_7dRhCHEhOopMQh619hA1bwaJyW1k8aNlLPTl3BotkP4M",
        "q": "sdQsQVz3tI7hmisAgiIjppOssEnZaZO0ONeRRDxBHGLe3BCo1FJoMMQryOAlglayjQnnWjQ-BpwUpa0r9YQhVLweoNEIig6Beph7iYRZgOHEiiTTgUIGgXAL6xhsby1PueUfT0xsN1Y7qt5f5EwOfu7tnFqNyJXIp9W1NQgU6fM",
        "dp": "kEpEnuJNfdqa-_VFb1RayJF6bjDmXQTcN_a47wUIZVMSWHR9KkMz41v0D_-oY7HVl73Kw0NagnVCaeH75HgeX5v6ZBQsrpIigynr3hl8T_LLNwIXebVnpFI2n5de0BTZ0DraxfZvOhYJEJV43NE8zWm7fdHLx2fxVFJ5mBGkXv0",
        "dq": "U_xJCnXF51iz5AP7MXq-K6YDIR8_t0UzEMV-riNm_OkVKAoWMnDZFG8R3sU98djQaxwKT-fsg2KjvbuTz1igBUzzijAvQESpkiUB82i2fNAj6rqJybpNKESq3FWkoL1dsgYsS19knJ31gDWWRFRHZFujjPyXiexz4BBmjK1Mc1E",
        "qi": "Uvb84tWiJF3fB-U9wZSPi7juGgrzeXS_LYtf5fcdV0fZg_h_5nSVpXyYyQ-PK218qEC5MlDkaHKRD9wBOe_eU_zJTNoXzB2oAcgl2MapBWUMytbiF84ghP_2K9UD63ZVsyrorSZhmsJIBBuqQjrmk0tIdpMdlMxLYhrbYwFxUqc",
        "kid": "kid-rsa-enc-oaep",
        "kty": "RSA"
      }
```

and the cipher text

```
"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.CuUuY9PH2wWjuLXd5O9LLFanwyt5-y-NzEpy9rC3A63tFsvdp8GWP1kRt1d3zd0bGqakwls623VQxzxqQ25j5gdHh8dKMl67xTLHt1Qlg36nI9Ukn7syq25VrzfrRRwy0k7isqMncHpzuBQlmfzPrszW7d13z7_ex0Uha869RaP-W2NNBfHYw26xIXcCSVIPg8jTLA7h6QmOetEej-NXXcWrRKQgBRapYy4iWrij9Vr3JzAGSHVtIID74tFOm01FdJj4s1M4IXegDbvAdQb6Vao1Ln5GolnTki4IGvH5FDssDHz6MS2JG5QBcITzfuXU81vDC00xzNEuMat0AngmOw.UjPQbnakkZYUdoDa.vcbS.WQ_bOPiGKjPSq-qyGOIfjA"
```
The header of this ciphertext is:
  ``` {"alg":"RSA1_5","enc":"A128GCM"}```
Hence the algorithm in the header does not match the algorithm in the key. Such ciphertexts should be rejected. The wrapped key is a valid RSA1_5 encrypted key. jose4j currently decrypts the ciphertext above without an exception. The problem with this behavior is that jose4j also allows chosen ciphertext attacks when the key uses RSA_OAEP. The attacker simply has to modify the header to and replace the algorithm with RSA1_5. Attempts to decrypt modified ciphertexts will then leak whether the decrypted message has valid PKCS #1 padding.


### Further Analysis
Fix Commit - https://bitbucket.org/b_c/jose4j/commits/63b86581e7bfcc2d9d04ee15caea4b5bfb911f59



### Timeline
**Date reported**: 01/27/2023
**Date fixed**: 02/09/2023
**Date disclosed**: 04/27/2023