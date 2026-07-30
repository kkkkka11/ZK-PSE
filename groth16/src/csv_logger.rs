use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::path::Path;

/// CSV日志记录工具，专门用于记录性能指标
/// 统一使用 metric,value 两列格式
pub struct CSVLogger {
    file_path: String,
}

impl CSVLogger {
    /// 创建新的CSV日志记录器
    pub fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
        }
    }

    /// 初始化CSV文件，写入表头
    pub fn initialize(&self) -> std::io::Result<()> {
        // 确保目录存在
        if let Some(parent) = Path::new(&self.file_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = File::create(&self.file_path)?;
        writeln!(file, "metric,value")?;
        Ok(())
    }

    /// 写入单个指标
    pub fn write_metric(&self, metric: &str, value: &str) -> std::io::Result<()> {
        // 如果文件不存在，先初始化
        if !Path::new(&self.file_path).exists() {
            self.initialize()?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;
        
        writeln!(file, "{},{}", metric, value)?;
        Ok(())
    }

    /// 写入多个指标
    pub fn write_metrics(&self, metrics: &[(&str, String)]) -> std::io::Result<()> {
        // 如果文件不存在，先初始化
        if !Path::new(&self.file_path).exists() {
            self.initialize()?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;
        
        let mut writer = BufWriter::new(file);
        
        for (metric, value) in metrics {
            writeln!(writer, "{},{}", metric, value)?;
        }
        
        writer.flush()?;
        Ok(())
    }

    /// 写入多个指标（值为不同类型）
    pub fn write_metrics_mixed(&self, metrics: &[(&str, &dyn ToString)]) -> std::io::Result<()> {
        let string_metrics: Vec<(&str, String)> = metrics
            .iter()
            .map(|(k, v)| (*k, v.to_string()))
            .collect();
        self.write_metrics(&string_metrics)
    }

    /// 批量写入指标（一次性写入，性能更好）
    pub fn write_all_metrics(&self, metrics: &[(&str, String)]) -> std::io::Result<()> {
        // 确保目录存在
        if let Some(parent) = Path::new(&self.file_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = File::create(&self.file_path)?;
        let mut writer = BufWriter::new(file);
        
        // 写入表头
        writeln!(writer, "metric,value")?;
        
        // 写入所有指标
        for (metric, value) in metrics {
            writeln!(writer, "{},{}", metric, value)?;
        }
        
        writer.flush()?;
        Ok(())
    }

    /// 追加时间戳指标
    pub fn write_timestamp(&self, metric: &str) -> std::io::Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        self.write_metric(metric, &timestamp.to_string())
    }

    /// 写入持续时间指标（毫秒）
    pub fn write_duration_ms(&self, metric: &str, start: std::time::Instant) -> std::io::Result<()> {
        let duration_ms = start.elapsed().as_millis();
        self.write_metric(metric, &duration_ms.to_string())
    }

    /// 安全写入（出错时不会panic）
    pub fn safe_write_metric(&self, metric: &str, value: &str) {
        if let Err(e) = self.write_metric(metric, value) {
            eprintln!("Warning: Failed to write metric {} to {}: {}", metric, self.file_path, e);
        }
    }

    /// 安全写入多个指标
    pub fn safe_write_metrics(&self, metrics: &[(&str, String)]) {
        if let Err(e) = self.write_metrics(metrics) {
            eprintln!("Warning: Failed to write metrics to {}: {}", self.file_path, e);
        }
    }

    /// 检查文件是否存在
    pub fn exists(&self) -> bool {
        Path::new(&self.file_path).exists()
    }

    /// 获取文件路径
    pub fn path(&self) -> &str {
        &self.file_path
    }
}

/// 便利宏：创建指标数组
#[macro_export]
macro_rules! metrics {
    ($($key:expr => $value:expr),* $(,)?) => {
        vec![$(($key, $value.to_string()),)*]
    };
}

/// 时间测量辅助结构
pub struct PerfTimer {
    start: std::time::Instant,
    name: String,
}

impl PerfTimer {
    pub fn start(name: &str) -> Self {
        Self {
            start: std::time::Instant::now(),
            name: name.to_string(),
        }
    }

    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_nanos() as f64 / 1_000_000.0
    }

    pub fn finish_and_log(&self, logger: &CSVLogger) -> std::io::Result<f64> {
        let elapsed = self.elapsed_ms();
        logger.write_metric(&self.name, &elapsed.to_string())?;
        Ok(elapsed)
    }

    pub fn finish_and_safe_log(&self, logger: &CSVLogger) -> f64 {
        let elapsed = self.elapsed_ms();
        logger.safe_write_metric(&self.name, &elapsed.to_string());
        elapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_csv_logger() {
        let temp_file = "test_metrics.csv";
        let logger = CSVLogger::new(temp_file);

        // 测试写入单个指标
        logger.write_metric("test_metric", "123").unwrap();
        
        // 测试写入多个指标
        let metrics = vec![
            ("metric1", "value1".to_string()),
            ("metric2", "value2".to_string()),
        ];
        logger.write_metrics(&metrics).unwrap();

        // 验证文件内容
        let content = fs::read_to_string(temp_file).unwrap();
        assert!(content.contains("metric,value"));
        assert!(content.contains("test_metric,123"));
        assert!(content.contains("metric1,value1"));

        // 清理测试文件
        fs::remove_file(temp_file).ok();
    }

    #[test]
    fn test_perf_timer() {
        let temp_file = "test_timer.csv";
        let logger = CSVLogger::new(temp_file);
        
        let timer = PerfTimer::start("test_duration_ms");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.finish_and_log(&logger).unwrap();
        
        assert!(elapsed >= 10.0);
        
        // 清理测试文件
        fs::remove_file(temp_file).ok();
    }
}