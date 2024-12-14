package com.hideakin.util;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

public class CommandLineParameters {

	private static class Parameter {

		private String _key;
		private String _operand;
		private String _description;
		private Function<CommandLineParameters, Boolean> _function;

		public Parameter(String key, String operand, String description, Function<CommandLineParameters, Boolean> function) {
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

	private final Map<String, Parameter> _mappings = new LinkedHashMap<>();
	private final Map<String, String> _aliases = new LinkedHashMap<>();
	private String[] _args = null;
	private int _index = 0;

	public CommandLineParameters() {
	}

	public CommandLineParameters add(String key, String description, Function<CommandLineParameters, Boolean> function) {
		_mappings.put(key, new Parameter(key, null, description, function));
		return this;
	}

	public CommandLineParameters add(String key, String operand, String description, Function<CommandLineParameters, Boolean> function) {
		_mappings.put(key, new Parameter(key, operand, description, function));
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

	public int intArgument() {
		try {
			return Integer.parseInt(_args[_index]);
		} catch (NumberFormatException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	public boolean process(String[] args) {
		_args = args;
		_index = -1;
		while (next()) {
			String key = argument();
			Parameter p = _mappings.get(key);
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
		for (Parameter p : _mappings.values()) {
			int n1 = p.key().length();
			int n2 = p.operand().length();
			int n = n1 + 1 + n2;
			if (w < n) {
				w = n;
			}
		}
		for (String k : _aliases.keySet()) {
			int n = k.length();
			if (w < n) {
				w = n;
			}
		}
		StringBuilder s = new StringBuilder();
		s.append("Syntax:\n");
		s.append("  java -jar THIS.jar parameters\n");
		s.append("Parameters:\n");
		String f = String.format("  %%-%ds  %%s\n", w); // format string
		String i = "\n" + TextHelpers.whitespaces(w + 4); // newline followed by indentation
		for (Parameter p : _mappings.values()) {
			s.append(String.format(f, p.key() + " " + p.operand(), p.description().replaceAll("\n", i)));
		}
		s.append("Aliases:\n");
		for (Map.Entry<String, String> e : _aliases.entrySet()) {
			s.append(String.format(f, e.getKey(), "is the alias of " + e.getValue()));
		}
		return s.toString();
	}

}
