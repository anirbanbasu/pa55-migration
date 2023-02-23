/**
 * 
 */
package tools.migration;

import java.io.Console;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.text.DateFormat;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import org.apache.commons.cli.*;

import prototype.pa55nyaps.core.NYAPSCore;
import prototype.pa55nyaps.crypto.AESCryptosystem;
import prototype.pa55nyaps.dataobjects.Ciphertext;
import prototype.pa55nyaps.dataobjects.PasswordDatabase;
import prototype.pa55nyaps.dataobjects.PasswordDatabaseEntry;

/**
 * @author abasu
 *
 */
public class PasswordDatabaseExporter {
	private static Gson gson = new GsonBuilder()
			.enableComplexMapKeySerialization()
			.serializeNulls()
			.setDateFormat(DateFormat.LONG)
			.disableHtmlEscaping()
			.setFieldNamingPolicy(FieldNamingPolicy.UPPER_CAMEL_CASE)
			.setPrettyPrinting()
			.setVersion(1.0)
			.create();

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Options options = new Options();
		
		Option helpOption = Option.builder("h")
				.longOpt("help")
				.required(false)
				.hasArg(false)
				.desc("Print this help message.")
				.type(Boolean.class)
				.build();
		options.addOption(helpOption);
		
		Option inputFilePathOption = Option.builder("i")
				.longOpt("input")
				.required(true)
				.hasArg(true)
				.argName("input file")
				.desc("Input PA55 NYAPS encrypted password database file path.")
				.type(String.class)
				.build();
		options.addOption(inputFilePathOption);
		
		Option outputFilePathOption = Option.builder("o")
				.longOpt("output")
				.required(false)
				.hasArg(true)
				.argName("output file")
				.desc("Output PA55 NYAPS plaintext password database file path. Output file will contain generated passwords if -g is specified.")
				.type(String.class)
				.build();
		options.addOption(outputFilePathOption);
		
		Option generatePasswordsOption = Option.builder("g")
				.longOpt("generate")
				.required(false)
				.hasArg(false)
				.desc("Generate passwords for each database entry.")
				.type(Boolean.class)
				.build();
		options.addOption(generatePasswordsOption);
		
		CommandLineParser parser = new DefaultParser();
		HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null; 

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp(PasswordDatabaseExporter.class.getName(), options, true);

            System.exit(1);
        }
        
        if(cmd.hasOption(helpOption)) {
        	formatter.printHelp(PasswordDatabaseExporter.class.getName(), options, true);
        }
        
        
		try {
	        String inputFilePath = cmd.getOptionValue(inputFilePathOption);
	        Console console = System.console();
			String password = new String(console.readPassword("Enter the password to decrypt %s: ", inputFilePath));
	        System.out.println("Processing " + inputFilePath);
	        
	        
			PasswordDatabaseExporter pde = new PasswordDatabaseExporter();
			PasswordDatabase database = pde.readDatabaseFromFile(new File(inputFilePath), password);
			
			if(cmd.hasOption(generatePasswordsOption)) {
				String masterSecret = new String(console.readPassword("Enter the master secret to generate passwords: "));
				int countEntries = database.getDatabase().values().size();
				int current = 0;
				for (PasswordDatabaseEntry entry : database.getDatabase().values()) {
					current++;
					System.out.print("Generating passwords: "+ current + " of " + countEntries + " \r");
					String dynamicHint = entry.getNotes().toString();
	    			dynamicHint += entry.getIssue();
	    			String generatedPassword = NYAPSCore.generatePasswordWithAESDRBG(masterSecret, dynamicHint, entry.getLength(), 
	    					entry.getCharacterTypes(), entry.getUserDefinedCharacters());
	    			entry.setGeneratedPassword(generatedPassword);
				}
				System.out.println();
			}
			
			if(cmd.hasOption(outputFilePathOption)) {
				pde.exportDabaseToJSON(database, new File(cmd.getOptionValue(outputFilePathOption)));
			}
			else {
				System.out.println(gson.toJson(database));
			}
		}
		catch (Exception ex) {
			ex.printStackTrace(System.err);
		}

		
	}
	
	protected PasswordDatabase readDatabaseFromFile(File file, String password) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, IOException {
		PasswordDatabase passwordDatabase = null;
		Scanner is;
		StringBuilder jsonct = new StringBuilder();
		is = new Scanner(file);
		while(is.hasNextLine()) {
			jsonct.append(is.nextLine());
		}
		is.close();
		Type ctType = new TypeToken<Ciphertext>(){}.getType();
		Ciphertext ciphertext = gson.fromJson(jsonct.toString(), ctType);
		String json = AESCryptosystem.getInstance().decryptWithHmac(ciphertext, password);
		Type dbType = new TypeToken<PasswordDatabase>(){}.getType();
		passwordDatabase = gson.fromJson(json.toString(), dbType);
		if(passwordDatabase==null) {
			throw new JsonSyntaxException(file.getName() + " contains a password database that cannot be deserialized.");
		}
		return passwordDatabase;
	}
	
	protected void exportDabaseToJSON(PasswordDatabase database, File file) throws IOException {
		FileWriter fw = new FileWriter(file);
		fw.write(gson.toJson(database));
		fw.close();
	}

}
