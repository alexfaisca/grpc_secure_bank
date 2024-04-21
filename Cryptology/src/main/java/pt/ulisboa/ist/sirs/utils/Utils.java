package pt.ulisboa.ist.sirs.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import javax.json.*;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Utils {
  public static byte[] readBytesFromPemFile(String resource) throws IOException {
    try (InputStream in =  new FileInputStream(resource)) {
      String pem = new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
      Pattern parse = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");
      String encoded = parse.matcher(pem).replaceFirst("$1");
      return Base64.getMimeDecoder().decode(encoded);
    } catch (IOException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  public static byte[] readBytesFromFile(String path) throws IOException {
    FileInputStream fis = new FileInputStream(path);
    byte[] content = new byte[fis.available()];
    int ignore = fis.read(content);
    fis.close();
    return content;
  }

  public static void writeBytesToFile(byte[] data, String filePath) {
    try {
      FileOutputStream outputStream = new FileOutputStream(filePath);
      outputStream.write(data);
      outputStream.close();
    } catch (IOException e) {
      System.out.println(e.getMessage());
    }
  }

  public static JsonObject createJson(List<String> fields, List<String> values) {
    JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
    for (int i = 0; i < fields.size(); i++) {
      String name = fields.get(i);
      String value = values.get(i);
      jsonBuilder.add(name, value);
    }
    return jsonBuilder.build();
  }

  public static byte[] serializeJson(JsonObject json) {
    return json.toString().getBytes();
  }

  public static JsonObject deserializeJson(byte[] jsonBytes) {
    return Json.createReader(new ByteArrayInputStream(jsonBytes)).readObject();
  }

  public static String byteToHex(byte[] bytes) {
    return Hex.encodeHexString(bytes);
  }

  public static byte[] hexToByte(String hex) {
    try {
      return Hex.decodeHex(hex);
    } catch (DecoderException e) {
      throw new IllegalArgumentException("String is not a hexadecimal number");
    }
  }

}
