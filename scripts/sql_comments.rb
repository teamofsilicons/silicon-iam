# frozen_string_literal: true

# Remove comments for lexical privilege checks, while keeping quoted SQL and
# line numbers. Dollar-quoted function/dynamic-SQL bodies are checked recursively
# so a comment cannot consume executable SQL after the closing delimiter.
module SqlComments
  def self.remove(source)
    text = source.b
    output = +"".b
    index = 0
    while index < text.length
      if text[index, 2] == "--"
        finish = text.index("\n", index) || text.length
        output << " " * (finish - index)
        index = finish
      elsif text[index, 2] == "/*"
        start = index
        index += 2
        depth = 1
        while index < text.length && depth.positive?
          if text[index, 2] == "/*"
            depth += 1
            index += 2
          elsif text[index, 2] == "*/"
            depth -= 1
            index += 2
          else
            index += 1
          end
        end
        output << text[start...index].gsub(/[^\n]/, " ")
      elsif ["'", '"'].include?(text[index])
        quote = text[index]
        start = index
        index += 1
        while index < text.length
          if text[index, 2] == quote * 2
            index += 2
          elsif text[index] == "\\"
            # Conservatively retain escaped string content as well as E'...'.
            index += 2
          elsif text[index] == quote
            index += 1
            break
          else
            index += 1
          end
        end
        output << text[start...index]
      elsif text[index] == "$" && (match = text.match(/\G\$(?:[a-zA-Z_][a-zA-Z_0-9]*)?\$/, index))
        delimiter = match[0]
        start = index + delimiter.length
        finish = text.index(delimiter, start)
        if finish
          output << delimiter << remove(text[start...finish]) << delimiter
          index = finish + delimiter.length
        else
          output << text[index]
          index += 1
        end
      else
        output << text[index]
        index += 1
      end
    end
    output.force_encoding(source.encoding)
  end
end
