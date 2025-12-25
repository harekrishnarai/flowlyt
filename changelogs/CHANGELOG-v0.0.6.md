# Flowlyt v0.0.6 Release Notes

## 🎉 Major Configuration Simplification

**Release Date**: September 3, 2025

This release introduces a major simplification to Flowlyt's configuration system, making it more user-friendly and following industry conventions.

## 🚀 **Major Changes**

### ⚠️ BREAKING CHANGE: Configuration System Redesign

**The `--config` flag has been completely removed** in favor of automatic `.flowlyt.yml` detection.

#### **Before (v0.0.5):**
```bash
# Required explicit config path
flowlyt scan --repo . --config .flowlyt.yml

# Error if config file didn't exist
flowlyt scan --repo .  # ❌ "Configuration file not found: .flowlyt.yml"
```

#### **After (v0.0.6):**
```bash
# Works perfectly without any configuration
flowlyt scan --repo .  # ✅ Uses sensible defaults

# Automatically uses .flowlyt.yml if present (no flag needed)
flowlyt scan --repo .  # ✅ + .flowlyt.yml auto-detected
```

## ✨ **New Features**

### 🔧 **Automatic Configuration Detection**
- **Auto-detect `.flowlyt.yml`**: If present in the current directory, it's automatically loaded
- **Zero-config operation**: Tool works perfectly without any configuration file
- **Convention over configuration**: Follows standard `.config.yml` naming pattern

### 🎯 **Simplified User Experience**
- **No more config paths**: Eliminated the need to manage configuration file paths
- **No more "file not found" errors**: Configuration is truly optional
- **Reduced CLI complexity**: Fewer flags to remember

## 🛠️ **Improvements**

### 📁 **Configuration Management**
- **Smart defaults**: Sensible default configuration when no `.flowlyt.yml` exists
- **Backward compatible**: Existing `.flowlyt.yml` files work unchanged
- **Optional customization**: Configuration provides advanced features only when needed

### 🐛 **Bug Fixes**
- **Fixed mandatory config requirement**: Resolved issue where basic scan commands failed without config file
- **Eliminated validation errors**: No more false errors about missing configuration files
- **Improved error messages**: Better guidance when configuration syntax issues occur

## 📚 **Documentation Updates**

### 📖 **Updated Guides**
- **Quick Start Guide**: Emphasizes zero-config operation with optional configuration examples
- **Troubleshooting Guide**: Updated configuration section to reflect new behavior
- **Installation Guide**: Updated version references and installation commands

### 🔄 **Migration Guide**

#### **For Existing Users:**

1. **Remove `--config` flags** from your commands:
   ```bash
   # Old
   flowlyt scan --repo . --config .flowlyt.yml
   
   # New  
   flowlyt scan --repo .
   ```

2. **Rename config files** to `.flowlyt.yml` in project root:
   ```bash
   # If you have custom config names
   mv my-custom.yml .flowlyt.yml
   ```

3. **Or simply omit configuration** entirely (uses sensible defaults):
   ```bash
   # Just works!
   flowlyt scan --repo .
   ```

#### **No Action Required If:**
- ✅ You already use `.flowlyt.yml` in your project root
- ✅ You don't use configuration files at all
- ✅ You use default settings

## 📊 **Impact Summary**

### ✅ **Benefits**
- **50% reduction in CLI complexity** (removed config flag management)
- **Zero-config operation** for immediate use
- **100% backward compatibility** for existing `.flowlyt.yml` files
- **Follows industry conventions** (`.config.yml` pattern)

### ⚡ **Performance**
- **Same scanning performance** - no performance impact
- **Faster startup** - simplified configuration loading
- **Reduced error handling** - fewer edge cases

## 🔍 **Technical Details**

### **Configuration Loading Logic:**
1. Look for `.flowlyt.yml` in current directory
2. If found, load and validate configuration
3. If not found, use sensible defaults
4. Apply CLI flag overrides (output format, severity, etc.)

### **Supported Configuration:**
- **Same YAML structure** as before
- **All existing options** remain available
- **Optional in every aspect** - any section can be omitted

## 🚨 **Breaking Changes**

### **Removed:**
- ❌ `--config` / `-c` CLI flag
- ❌ Custom configuration file path support
- ❌ Configuration file path validation

### **Migration Required:**
- 🔄 Remove `--config` flags from scripts/CI
- 🔄 Rename config files to `.flowlyt.yml`
- 🔄 Update documentation references

## 🆕 **What's Next**

This release lays the foundation for:
- **Enhanced workflow discovery** (Issue #6)
- **Improved rule customization**
- **Better CI/CD integration patterns**

## 📥 **Installation**

### **Recommended (bypasses Go proxy cache):**
```bash
GOPRIVATE=github.com/harekrishnarai/flowlyt go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@latest
```

### **Direct version install:**
```bash
go install github.com/harekrishnarai/flowlyt/cmd/flowlyt@v0.0.6
```

### **Verify installation:**
```bash
flowlyt --version
# Should output: flowlyt version 0.0.6
```

## 🙏 **Acknowledgments**

This release focuses on user experience improvements based on community feedback. The configuration simplification makes Flowlyt more accessible while maintaining all existing functionality.

---

**Full Changelog**: https://github.com/harekrishnarai/flowlyt/compare/v0.0.5...v0.0.6
