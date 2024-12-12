package com.hideakin.mycrypt;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

public class CommandLineParameters {

	private static class ParameterInfo {

		private String _key;
		private String _operand;
		private String _description;
		private Function<CommandLineParameters, Boolean> _function;

		public ParameterInfo(String key, String operand, String description, Function<CommandLineParameters, Boolean> function) {
			_key = key;
			_operand = operand;
			_description = description;
			_function = function;
		}

		public String key() {
			return _key;
		}

		public String operand() {
			return _operand != null ? _operand : "";
		}

		public String description() {
			return _description;
		}

		public Function<CommandLineParameters, Boolean> function() {
			return _function;
		}

	}

	private final Map<String, ParameterInfo> _mappings = new LinkedHashMap<>();
	private final Map<String, String> _aliases = new LinkedHashMap<>();
	private String[] _args = null;
	private int _index = 0;

	public CommandLineParameters() {
	}

	public CommandLineParameters add(String key, String description, Function<CommandLineParameters, Boolean> function) {
		_mappings.put(key, new ParameterInfo(key, null, description, function));
		return this;
	}

	public CommandLineParameters add(String key, String operand, String description, Function<CommandLineParameters, Boolean> function) {
		_mappings.put(key, new ParameterInfo(key, operand, description, function));
		return this;
	}
	
	public CommandLineParameters addAlias(String alias, String key) {
		_aliases.put(alias, key);
		return this;
	}

	public boolean next() {
		return ++_index < _args.length;
	}

	public String argument() {
		return _args[_index];
	}

	public boolean process(String[] args) {
		_args = args;
		_index = -1;
		while (next()) {
			String key = argument();
			ParameterInfo p = _mappings.get(key);
			if (p == null) {
				String key2 = _aliases.get(key);
				if (key2 != null) {
					p = _mappings.get(key2);
				}
				if (p == null) {
					throw new RuntimeException("Bad syntax: " + key);
				}
			}
			if (!p.function().apply(this)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		int w = 0;
		for (ParameterInfo p : _mappings.values()) {
			int n1 = p.key().length();
			int n2 = p.operand().length();
			int n = n1 + 1 + n2;
			if (w < n) {
				w = n;
			}
		}
		StringBuilder s = new StringBuilder();
		s.append("Syntax:\n");
		s.append("  java -jar THIS.jar parameters\n");
		s.append("Parameters:\n");
		String f = String.format("  %%-%ds  %%s\n", w);
		for (ParameterInfo p : _mappings.values()) {
			s.append(String.format(f, p.key() + " " + p.operand(), p.description().replaceAll("\n", "\n" + StringHelpers.whitespaces(w + 4))));
		}
		s.append("Aliases:\n");
		for (Map.Entry<String, String> entry : _aliases.entrySet()) {
			s.append(String.format(f, entry.getKey(), "is the alias of " + entry.getValue()));
		}
		return s.toString();
	}

}
