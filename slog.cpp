#include <iostream>
#include <fstream>
#include <streambuf>
#include <mutex>
#include <string>
#include <string_view>
#include <chrono>
#include <filesystem>
#include <cassert>
#include <thread>
#include <sstream>
/*
// CSimpleLogger.h
//
// 设计思路：
// 这个简单的日志系统旨在提供一种灵活的方式记录日志，支持多线程环境下的安全日志记录，
// 并可以根据需要选择是否启用基于XOR的简单加密功能。此外，该系统还支持日志文件的自动轮换，当达到指定大小时会创建新的日志文件。
//
// 使用细节：
// 1. 日志级别：定义了三种基本的日志级别（信息、警告、错误），可以通过枚举类 LogLevel 来指定。
// 2. 日志输出流：提供了 CLogStream 类模板，用于构造一个日志消息。用户可以通过流式接口
//    将消息附加到当前的日志条目中。
// 3. 日志类：CSimpleLogger 是一个模板类，允许用户根据需要选择是否启用加密以及是否支持多线程。
// 4. 日志文件管理：支持日志文件的最大大小及最大文件数量配置，当达到配置值时会自动进行日志文件轮换。
// 5. 时间戳与线程ID：每个日志条目都会包含时间戳和记录日志时所在的线程ID。
// 6. 文件路径：会自动提取并记录日志输出位置的文件名及行号。
// 7. 字符类型：通过预处理宏 LOG_USE_WCHAR 可以选择使用宽字符或普通字符。
// 7. 精简短小的代码就是高可扩展性。使用者可以按需修改源码，实现输出日志格式的自定义，加密算法，压缩算法实现加密和压缩等。
//
// 示例用法：
// CSimpleLogger<> logger("example_log", 1024 * 1024 * 20, 5); // 创建一个日志实例，最大20MB，最多保留5个日志文件
// SIMPLE_LOG_INFO(logger) << "This is an info message.";
// SIMPLE_LOG_WARNING(logger) << "This is a warning message.";
// SIMPLE_LOG_ERROR(logger) << "This is an error message.";
//
// 如果编译器支持 C++20：
// SIMPLE_LOG_INFO_FMT(logger, "{} message.", "Info");
// SIMPLE_LOG_WARNING_FMT(logger, "{} message.", "Warning");
// SIMPLE_LOG_ERROR_FMT(logger, "{} message.", "Error");
//
// 注意事项：
// - 日志记录功能默认为线程安全，如果不需要线程安全，可以在创建日志对象时指定。
// - 日志文件的名称和路径应该具有足够的权限允许程序进行读写操作。
// - 日志记录可能会消耗较多的磁盘空间，特别是在高流量的应用场景下。
// - 如果启用了加密功能，请确保有适当的方法解密日志文件以便于后续查看或分析。
// - CSimpleLogger和CQueuedLogger的差异：
//       0. CSimpleLogger会在使用者写入日志时写入文件和加密/压缩；CQueuedLogger则将日志交给专门的日志线程写入文件和加密/压缩。
//       1. CSimpleLogger适合于大部分的场景，使用简单可靠，性能高。
//       2. 对于性能特别敏感，日志量特别大，使用者对日志调用的时间要求极高的场景，可以使用CQueuedLogger。
//       3. CQueuedLogger的优点就是选择合适的Queued大小，就可以做到几乎不会阻塞使用者。
//       4. 另外，对于复杂加密和压缩的场景，CQueuedLogger的优势也更好，因为压缩逻辑在独立线程完成，不影响使用者。
//       5. CQueuedLogger的缺点是需要额外消耗一个线程资源。
//
// - 本日志系统的代码设计力求简洁明了，使得用户能够轻松理解其内部逻辑并按需进行扩展。通过精简核心功能，不仅降低了维护成本，还为用户提供了广泛的自定义空间。
//   使用者可以根据自己的需求轻松修改源码，实现对日志输出格式的定制，例如调整时间戳格式、增加额外的信息字段等。此外，加密算法和压缩算法的实现也可以在此基础上进行扩展，以适应不同的应用场景，如对敏感数据进行加密保护或对大量日志数据进行压缩存储，从而提高存储效率和安全性。
*/

// 通过定义SLOG_CONFIG_USE_WCHAR=1使用wchar_t版本。默认为char。
#ifndef SLOG_CONFIG_USE_WCHAR
#define SLOG_CONFIG_USE_WCHAR 0
#endif

#define SLOG_CONFIG_ENCRYPTION_XOR_KEY 'L' // 加密密钥

namespace SLog {

#if SLOG_CONFIG_USE_WCHAR
#define SLOG_CONFIG_FILE_SUFFIX L".log" // 日志文件后缀
	typedef wchar_t Char;
	typedef std::char_traits<Char>::int_type CharInt;
	typedef std::wstreambuf StringBuf;
	typedef std::wfilebuf FileBuffer;
	typedef std::wostringstream OutputStream;
	typedef std::wostream OutputStreamType;
	typedef std::wstring StringType;
	typedef std::wstring_view StringView;
	typedef std::wstringstream StringStream;
	inline StringType numberToString(std::size_t n) {
		return std::to_wstring(n);
	}
#define SLOG_LITERAL(x) L ## x
#define SLOG_LITERAL1(x) SLOG_LITERAL(x)
#define __SLOG_FILE__ SLOG_LITERAL1(__FILE__)

#else
#define SLOG_CONFIG_FILE_SUFFIX ".log" // 日志文件后缀
	typedef char Char;
	typedef std::char_traits<Char>::int_type CharInt;
	typedef std::streambuf StringBuf;
	typedef std::filebuf FileBuffer;
	typedef std::ostringstream OutputStream;
	typedef std::ostream OutputStreamType;
	typedef std::string StringType;
	typedef std::string_view StringView;
	typedef std::stringstream StringStream;
	inline StringType numberToString(std::size_t n) {
		return std::to_string(n);
	}
#define SLOG_LITERAL(x) x
#define __SLOG_FILE__ __FILE__
#endif



	namespace SimpleLogEncryption {


		template<bool enableEncryption>
		class XOREncryptionBuffer : public StringBuf {
		public:
			XOREncryptionBuffer(Char key) : encryptionKey(key) {}
		protected:

			// 日志后处理核心逻辑，如果需要定制化加密逻辑，增加压缩逻辑，修改这overflow和xsputn这两个函数即可。这里的XOR加密逻辑本质上是一个示例。

			virtual CharInt overflow(CharInt ch) override {
				if (!enableEncryption) {
					return fileBuffer.sputc(ch);
				}
				else {
					return fileBuffer.sputc(static_cast<Char>(ch) ^ encryptionKey);
				}
				return ch;
			}


			virtual std::streamsize xsputn(const Char* s, std::streamsize count) override {
				if (!enableEncryption) {
					return fileBuffer.sputn(s, count);
				}
				else {
					std::basic_string<Char> temp;
					temp.reserve(count);
					for (std::streamsize i = 0; i < count; ++i) {
						temp.push_back(s[i] ^ encryptionKey);
					}
					return fileBuffer.sputn(temp.data(), temp.size());
				}
			}


		public:
			FileBuffer fileBuffer;


		private:
			Char encryptionKey;
		};


		template<bool enableEncryption>
		class LogOutStream : public OutputStreamType {
		public:
			LogOutStream()
				: OutputStreamType(&streamBuf),
				streamBuf(SLOG_CONFIG_ENCRYPTION_XOR_KEY) {}


			bool is_open() {
				return streamBuf.fileBuffer.is_open();
			}
			void close() {
				streamBuf.fileBuffer.close();
			}
			int open(const StringType& FileName, int OpenFlag) {
				return streamBuf.fileBuffer.open(FileName.c_str(), OpenFlag) != nullptr;
			}
			long long tellp() {
				return streamBuf.fileBuffer.pubseekoff(0, std::ios_base::cur, std::ios_base::out);
			}


		private:
			XOREncryptionBuffer<enableEncryption> streamBuf;
		};
	}


	enum class LogLevel { INFO, WARNING, ERROR };


	template <class CLogger>
	class CLogStream {
	public:
		CLogStream(CLogger& logger, LogLevel level, const Char* file, int line)
			: logger(logger) {
			logger.onStartLogItem();
			// 日志格式化核心逻辑，如果需要定制化格式化，可以修改这部分代码即可。
			logger.stream() << logLevelToString(level) << std::this_thread::get_id();
			printCurrentTime(logger.stream());
			logger.stream() << extractFilename(file).data() << SLOG_LITERAL("@") << line << SLOG_LITERAL(": ");
		}


		~CLogStream() {
			logger.stream() << std::endl; // 换行
			logger.onEndLogItem();
		}


		template<typename T>
		CLogStream& operator<<(const T& msg) {
			logger.stream() << msg;
			return *this;
		}


		CLogStream(const CLogStream&) = delete;
		CLogStream& operator=(const CLogStream&) = delete;


	private:
		inline StringView extractFilename(const StringView& path) const {
#ifdef _WIN32
			auto path_separator = SLOG_LITERAL('\\');
#else
			auto path_separator = SLOG_LITERAL('/');
#endif
			size_t pos = path.find_last_of(path_separator);
			if (pos != StringView::npos) {
				return path.substr(pos + 1);
			}
			return std::move(path);
		}


		template<class StreamType>
		inline void printCurrentTime(StreamType& stream) {
			auto now = std::chrono::system_clock::now();
			std::time_t now_time = std::chrono::system_clock::to_time_t(now);
			std::tm now_tm = {};
#ifdef _WIN32
			if (localtime_s(&now_tm, &now_time) == 0) {
#else
			if (localtime_r(&now_time, &now_tm)) {
#endif // _WIN32
				long long now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
				char buffer[32];
				std::snprintf(buffer, sizeof(buffer), " %04d-%02d-%02d %02d:%02d:%02d.%03d\t",
					now_tm.tm_year + 1900, now_tm.tm_mon + 1, now_tm.tm_mday,
					now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec, (int)(now_ms % 1000));
				stream << buffer;
			}
			else {
				assert(false);
			}
			}


		inline const char* logLevelToString(LogLevel level) const {
			switch (level) {
			case LogLevel::INFO:
				return "INFO ";
			case LogLevel::WARNING:
				return "WARN ";
			case LogLevel::ERROR:
				return "ERRO ";
			default:
				return "UNKNOWN ";
			}
		}


	private:
		CLogger& logger;
		};


	template<bool enableEncryption = false, bool bSupportMulitThread = true>
	class CSimpleLogger {
	public:
		CSimpleLogger(const StringType& filename, size_t maxSize = 20 * 1024 * 1024, size_t maxFiles = 4)
			: log_file_prefix(filename),
			max_file_size(maxSize),
			max_files(maxFiles) {
			initializeLoggerWithOutLock();
		}


		~CSimpleLogger() {
			if (log_stream.is_open()) {
				log_stream.close();
			}
		}


		auto log(LogLevel level, const Char* file, int line) {
			return CLogStream<CSimpleLogger>(*this, level, file, line);
		}


		void onStartLogItem() {
			if (bSupportMulitThread) {
				log_mutex.lock();
			}
		}


		void onEndLogItem() {
			checkAndRotateWithOutLock();
			if (bSupportMulitThread) {
				log_mutex.unlock();
			}
		}


		auto& stream() {
			return this->log_stream;
		}


	private:
		SimpleLogEncryption::LogOutStream<enableEncryption> log_stream;


	private:
		std::mutex log_mutex;
		StringType log_file_prefix;
		size_t max_file_size;
		size_t max_files;


		void initializeLoggerWithOutLock() {
			try {
				if (log_stream.is_open()) {
					log_stream.close();
				}
				log_stream.open(log_file_prefix + SLOG_CONFIG_FILE_SUFFIX, std::ios::app);
				for (int i = 0; !log_stream.is_open(); ++i) {
					log_stream.open(log_file_prefix + SLOG_LITERAL(".") + numberToString(i) + SLOG_LITERAL(".temp") + SLOG_CONFIG_FILE_SUFFIX, std::ios::app);
				}
			}
			catch (...) {
				assert(false);
			}
		}


		void rotateLogsWithOutLock() {
			try {
				log_stream.close();
				if (std::filesystem::exists(log_file_prefix + SLOG_LITERAL(".") + numberToString(max_files) + SLOG_CONFIG_FILE_SUFFIX)) {
					std::filesystem::remove(log_file_prefix + SLOG_LITERAL(".") + numberToString(max_files) + SLOG_CONFIG_FILE_SUFFIX);
				}
				for (size_t i = max_files; i > 1; --i) {
					auto src = log_file_prefix + SLOG_LITERAL(".") + numberToString(i - 1) + SLOG_CONFIG_FILE_SUFFIX;
					auto dst = log_file_prefix + SLOG_LITERAL(".") + numberToString(i) + SLOG_CONFIG_FILE_SUFFIX;
					if (std::filesystem::exists(src)) {
						std::filesystem::rename(src, dst);
					}
				}
				if (std::filesystem::exists(log_file_prefix + SLOG_CONFIG_FILE_SUFFIX)) {
					std::filesystem::rename(log_file_prefix + SLOG_CONFIG_FILE_SUFFIX, log_file_prefix + SLOG_LITERAL(".1") + SLOG_CONFIG_FILE_SUFFIX);
				}
			}
			catch (...) {
				assert(false);
			}
		}


		void checkAndRotateWithOutLock() {
			if (log_stream.tellp() >= static_cast<std::streamoff>(max_file_size)) {
				rotateLogsWithOutLock();
				initializeLoggerWithOutLock();
			}
		}
	};


	//////////////////////////////////////////////////////////////////////////


	// 线程队列版本的日志器
	// 原理：使用生产者消费者模型，写入日志在另一个线程。写入日志的调用可以返回非常快，提高使用者性能。通过调节queuedSize可以获得一个内存和性能平衡的最佳参数。
	template<bool enableEncryption = false, int queuedSize = 500>
	class CQueuedLogger {
	private:
		template <typename T> class CProducerConsumer {
		public:
			CProducerConsumer(int max_capacity = 10) : capacity(max_capacity) {};
			void produce(T value) {
				std::unique_lock<std::mutex> lock(mtx);
				while (buffer.size() == capacity) { // 如果缓冲区满了，则等待
					cond_var.wait(lock);
				}
				buffer.push_back(std::move(value));
				cond_var.notify_one(); // 通知消费者
			}


			void consume(std::vector<T>& out) {
				std::unique_lock<std::mutex> lock(mtx);
				while (buffer.empty()) { // 如果缓冲区为空，则等待
					cond_var.wait(lock);
				}
				assert(out.empty());
				std::swap(out, buffer);//直接把整个buffer都返回
				cond_var.notify_one(); // 通知生产者
			}


		private:
			std::vector<T> buffer;
			const size_t capacity = 10; // 缓冲区容量
			std::mutex mtx;
			std::condition_variable cond_var;
		};


	public:
		CQueuedLogger(const StringType& filename, size_t maxSize = 20 * 1024 * 1024, size_t maxFiles = 4) :
			m_singleThreadLoger(filename, maxSize, maxFiles),
			producerConsumer(queuedSize),
			write_log_thread([this]() {this->logThreadProc(); }) {
		}


		~CQueuedLogger() {
			need_exit_log_thread = true;
			write_log_thread.join();
		}


		// 下面的public是Log接口，协约式编程 必须实现
		inline auto log(LogLevel level, const Char* file, int line) {
			return CLogStream<CQueuedLogger>(*this, level, file, line);
		}


		void onStartLogItem() {
		}


		void onEndLogItem() {
			// 结果在stream里面
			producerConsumer.produce(stream().str());
			stream().str(StringType());//清空
		}


		auto& stream() {
			static thread_local StringStream log_stream;
			return log_stream;
		}
	private:


		void logThreadProc() {
			while (need_exit_log_thread == false) {
				m_singleThreadLoger.onStartLogItem();
				std::vector<StringType> logs;
				producerConsumer.consume(logs);
				for (auto it = logs.begin(); it != logs.end(); ++it) {
					m_singleThreadLoger.stream() << *it;
					//m_singleThreadLoger.onEndLogItem(); onEndLogItem应该要在这里调用，但是我们为了追求更高的性能，选择最后调用。
				}
				m_singleThreadLoger.onEndLogItem();
			}
		}


	private:
		CSimpleLogger<enableEncryption, false> m_singleThreadLoger;
		CProducerConsumer<StringType> producerConsumer;
		std::thread write_log_thread;
		bool need_exit_log_thread = false;
	};


	}



// 宏用于自动添加文件名和行号
#define SIMPLE_LOG_INFO(logger) logger.log(LogLevel::INFO, __SLOG_FILE__, __LINE__)
#define SIMPLE_LOG_WARNING(logger) logger.log(LogLevel::WARNING, __SLOG_FILE__, __LINE__)
#define SIMPLE_LOG_ERROR(logger) logger.log(LogLevel::ERROR, __SLOG_FILE__, __LINE__)


#if (__cplusplus >= 202002L || _MSVC_LANG >= 202002L)
#include <format>
// 使用 std::format 实现格式化日志记录
#define SIMPLE_LOG_INFO_FMT(logger, fmt, ...) SIMPLE_LOG_INFO(logger) << std::format(fmt, __VA_ARGS__)
#define SIMPLE_LOG_WARNING_FMT(logger, fmt, ...) SIMPLE_LOG_WARNING(logger) << std::format(fmt, __VA_ARGS__)
#define SIMPLE_LOG_ERROR_FMT(logger, fmt, ...) SIMPLE_LOG_ERROR(logger) << std::format(fmt, __VA_ARGS__)
#endif




//////////////////////////////////////////////////////////////////////////
// 以下是测试用例:


using namespace SLog;

void logMessages(CSimpleLogger<false, true>& logger, int thread_id, int message_count) {
	for (int i = 0; i < message_count / 3; ++i) {
		SIMPLE_LOG_INFO(logger) << SLOG_LITERAL("Thread ") << thread_id << SLOG_LITERAL(" logging message ") << i;
		SIMPLE_LOG_WARNING(logger) << SLOG_LITERAL("Test Warning") << i;
		SIMPLE_LOG_ERROR(logger) << SLOG_LITERAL("Test Error") << i;

#if (__cplusplus >= 202002L || _MSVC_LANG >= 202002L)
		SIMPLE_LOG_INFO_FMT(logger, SLOG_LITERAL("fmt log: {}"), i); // c++ 20 支持
#endif
	}
	std::cout << std::chrono::system_clock::now() << " ## logMessages thread id:" << thread_id << " Done!\n";
}


void logMessagesQueued(CQueuedLogger<false>& logger, int thread_id, int message_count) {
	for (int i = 0; i < message_count / 3; ++i) {
		SIMPLE_LOG_INFO(logger) << SLOG_LITERAL("Thread ") << thread_id << SLOG_LITERAL(" logging message ") << i;
		SIMPLE_LOG_WARNING(logger) << SLOG_LITERAL("Test Warning") << i;
		SIMPLE_LOG_ERROR(logger) << SLOG_LITERAL("Test Error") << i;

#if (__cplusplus >= 202002L || _MSVC_LANG >= 202002L)
		SIMPLE_LOG_INFO_FMT(logger, SLOG_LITERAL("fmt log: {}"), i); // c++ 20 支持
#endif
	}
	std::cout << std::chrono::system_clock::now() << " @@ logMessagesQueued thread id:" << thread_id << " Done!\n";
}


int main() {
	try {
		CSimpleLogger<false> logger(SLOG_LITERAL("simple_log"));
		CQueuedLogger<false> queuedLogger(SLOG_LITERAL("queued_log"));

		const int num_threads = 20;
		const int messages_per_thread = 10000;

		std::cout << "Start test at:" << std::chrono::system_clock::now() << " use " << num_threads << " thread ,each write " << messages_per_thread << " logs" << std::endl;

		std::vector<std::thread> threads;
		for (int i = 0; i < num_threads; ++i) {
			threads.emplace_back(logMessages, std::ref(logger), i, messages_per_thread);
			threads.emplace_back(logMessagesQueued, std::ref(queuedLogger), i, messages_per_thread);
		}

		for (auto& t : threads) {
			t.join();
		}

		std::cout << "Logging complete. Check log.txt for results." << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Logging failed: " << e.what() << std::endl;
	}

	return 0;
}