package tools.migration.dataobjects;

import com.opencsv.bean.*;

import prototype.pa55nyaps.dataobjects.PasswordDatabaseEntry;

public class CSVBeanStandardPasswordEntry {
	@CsvBindByName(column = "ID")
	private String id;
	
	@CsvBindByName(column = "Description")
	private String description;
	
	@CsvBindByName(column = "URL")
	private String url;
	
	@CsvBindByName(column = "Username")
	private String username;
	
	@CsvBindByName(column = "Password")
	private String password;
	
	@CsvBindByName(column = "Notes")
	private String notes;
	
	
	public CSVBeanStandardPasswordEntry() {	
	
	}
	
	public CSVBeanStandardPasswordEntry(PasswordDatabaseEntry entry) {
		this.id = entry.getId();
		this.description = "Service: " + entry.getNotes().getServiceName() + "; Length: " + entry.getLength() + "; Issue: " + entry.getIssue();
		this.url = entry.getNotes().getServiceLink();
		this.username = entry.getNotes().getUserID();
		this.password = entry.getGeneratedPassword();
		this.notes = entry.getNotes().getAdditionalInfo();
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getNotes() {
		return notes;
	}

	public void setNotes(String notes) {
		this.notes = notes;
	}

}
