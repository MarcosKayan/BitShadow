README v.2.0 — BitShadow 2.0

Esta é a segunda versão do BitShadow, atualizada e ampliada com foco em segurança, flexibilidade e experiência do usuário. Abaixo estão as principais melhorias implementadas em relação à versão original:

1. 🔐 Suporte a Argon2id
   - Adicionado novo sistema de derivação de chaves baseado no algoritmo Argon2id.
   - Parâmetros utilizados: memória 512 MiB, tempo 6 ciclos, paralelismo 4, saída de 64 bytes.
   - Muito mais resistente contra ataques modernos com GPU/ASIC.

2. 🔄 Escolha entre PBKDF2 e Argon2id na interface
   - O usuário pode selecionar o método de derivação diretamente na aba de encriptação.
   - Interface radio-button intuitiva entre os dois algoritmos.

3. 🎯 Detecção automática do algoritmo na desencriptação
   - O programa detecta sozinho se o arquivo foi encriptado com PBKDF2 ou Argon2id.
   - Isso permite compatibilidade reversa com arquivos antigos e interoperabilidade futura.

4. 🖼️ Interface gráfica aprimorada
   - A tela inclui agora seletor de KDF abaixo do campo de senha.
   - Melhor organização visual para campos, botões e progressos.

5. 🧪 Robustez criptográfica reforçada
   - Salt do Argon2 ampliado para 32 bytes.
   - Mantida compatibilidade com PBKDF2 (16 bytes + 1 milhão de iterações).

6. 🛠️ Compatibilidade com versões anteriores
   - Arquivos PNG gerados com BitShadow 1.0 podem ser desencriptados normalmente.
   - Fluxo de desencriptação totalmente automatizado.

Esta versão representa um avanço técnico e estrutural, mantendo a simplicidade de uso e a robustez da proposta original.

Ass. Marcos Kayan Niquelatte
