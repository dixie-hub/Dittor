package dittor.testing;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

// Corrompe um digito hex de um campo de um payload da bridge preservando a sintaxe JSON a volta, para os testes de rejeicao de prova invalida
// Como usar: PayloadCorruptor <entrada> <saida> <indice-campo>
// Indices: 0=context 1=pk 2=nym 3=zkp 4=g1x 5=credential 6=dleqChallenge 7=dleqResponse 8=nodeId 9=familyIds
public class PayloadCorruptor {

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Erro: PayloadCorruptor <entrada> <saida> <indice-campo> [delimitador]");
            System.err.println("Delimitador por omissao: '|' (bridge_payload.txt) e ' ' para dittor_proof.txt.");
            System.exit(1);
        }

        String delimiter = args.length > 3 ? args[3] : "|";
        String content = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8).trim();
        String[] fields = content.split(java.util.regex.Pattern.quote(delimiter), -1);
        int idx = Integer.parseInt(args[2]);

        if (idx < 0 || idx >= fields.length) {
            System.err.println("Indice fora do intervalo (0.." + (fields.length - 1) + ")");
            System.exit(1);
        }

        String field = fields[idx];
        int pos = field.length() - 1;
        while (pos >= 0 && !isHexDigit(field.charAt(pos))) {
            pos--;
        }
        if (pos < 0) {
            System.err.println("Campo " + idx + " nao tem nenhum digito hex para corromper: " + field);
            System.exit(1);
        }

        char original = field.charAt(pos);
        char corrupted = flipHexDigit(original);
        fields[idx] = field.substring(0, pos) + corrupted + field.substring(pos + 1);

        String result = String.join(delimiter, fields);
        Files.write(Paths.get(args[1]), result.getBytes(StandardCharsets.UTF_8));

        System.out.println("Campo " + idx + ": digito '" + original + "' -> '" + corrupted + "' na posicao " + pos);
        System.out.println("Escrito em " + args[1]);
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static char flipHexDigit(char c) {
        char lower = Character.toLowerCase(c);
        char flipped;
        if (lower == 'f') {
            flipped = '0';
        } else if (lower == '9') {
            flipped = 'a';
        } else {
            flipped = (char) (lower + 1);
        }
        return Character.isUpperCase(c) ? Character.toUpperCase(flipped) : flipped;
    }
}
