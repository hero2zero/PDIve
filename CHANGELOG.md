# PDIve Changelog

All notable changes to the PDIve project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2025-09-25

### 🚀 New Features
- **Intelligent Masscan Sudo Handling**: Automatic detection of sudo access for masscan
- **Enhanced Error Messages**: Clear, actionable error messages and suggestions
- **Graceful Fallback**: Seamless fallback to built-in port scanner when masscan sudo unavailable
- **Sudo Access Verification**: Pre-flight checks for masscan privileges using `sudo -n`

### 🔧 Improvements
- **Better User Experience**: Informative messages about masscan requirements and solutions
- **Enhanced Documentation**: Complete rewrite of all documentation (README, INSTALL, USAGE)
- **Comprehensive Installation Guide**: Detailed INSTALL.md with multiple installation methods
- **Detailed Usage Examples**: Extensive USAGE.md with real-world scenarios

### 🐛 Bug Fixes
- **Fixed**: Masscan permission denied errors now properly handled
- **Fixed**: Clear error messaging when sudo access is required but not available
- **Fixed**: Improved error context for troubleshooting masscan issues

### 📚 Documentation
- **Added**: INSTALL.md - Comprehensive installation guide
- **Added**: USAGE.md - Detailed usage examples and workflows
- **Added**: CHANGELOG.md - Version tracking and change history
- **Updated**: README.md with v1.3 features and masscan sudo requirements
- **Updated**: All version strings and User-Agent headers to v1.3

### 🔒 Security
- **Enhanced**: Better permission handling for masscan operations
- **Improved**: Clear guidance on running with appropriate privileges
- **Added**: Security considerations for sudo configuration

### 💻 Technical Changes
- **Modified**: Masscan command construction to include `sudo` prefix
- **Added**: Sudo access verification using `sudo -n masscan --help`
- **Enhanced**: Error handling and fallback logic for masscan failures
- **Updated**: All version references from 1.2 to 1.3

### ⚙️ Configuration
- **Added**: Instructions for passwordless sudo configuration
- **Added**: Alternative deployment methods (Docker, system-wide)
- **Enhanced**: Troubleshooting guides for common issues

## [1.2.0] - Previous Release

### 🚀 Major Changes
- **Rebranded**: Changed from "Roverly" to "PDIve"
- **Enhanced Workflow**: Improved active discovery mode with amass → masscan → nmap pipeline
- **Passive Mode Refinement**: Simplified passive mode to use only OWASP Amass

### 🔧 Improvements
- **Streamlined Discovery**: Active mode now uses 4-phase approach
- **Better Integration**: Improved amass integration for both modes
- **Enhanced Reporting**: Specialized reports for passive vs active modes

### 📊 Features
- **Phase 1**: Amass passive subdomain discovery
- **Phase 2**: Host discovery and connectivity verification
- **Phase 3**: Fast port scanning with masscan (1-65535)
- **Phase 4**: Detailed service enumeration with nmap

### 🐛 Bug Fixes
- **Fixed**: Improved amass error handling and timeout management
- **Fixed**: Better masscan integration and output parsing
- **Enhanced**: More reliable host discovery process

### 📚 Documentation
- **Updated**: Complete documentation rewrite for PDIve branding
- **Added**: Detailed workflow explanations
- **Enhanced**: Better usage examples and troubleshooting guides

## [1.1.0] - Previous Release

### 🚀 New Features
- **Passive Discovery Mode**: Added stealth reconnaissance capabilities
- **Multiple Discovery Sources**: Integration with Amass, DNSDumpster, and crt.sh
- **Dual-Mode Operation**: Choice between active and passive discovery

### 🔧 Improvements
- **Enhanced Amass Integration**: Better passive subdomain enumeration
- **Multi-Source Discovery**: Combines results from multiple OSINT sources
- **Improved Error Handling**: Better handling of external tool failures

### 📊 Discovery Methods
- **OWASP Amass**: Passive subdomain enumeration
- **DNSDumpster**: Web-based DNS reconnaissance
- **Certificate Transparency**: crt.sh certificate log analysis

### 🐛 Bug Fixes
- **Fixed**: DNS resolution timeout issues
- **Fixed**: Better handling of rate limiting from external sources
- **Enhanced**: More robust error recovery mechanisms

## [1.0.0] - Initial Release (as Roverly)

### 🚀 Initial Features
- **Active Network Scanning**: Basic active discovery capabilities
- **Port Scanning**: TCP port enumeration
- **Service Detection**: Basic service identification
- **Host Discovery**: Ping and port-based host detection

### 📊 Core Functionality
- **Network Discovery**: IP range and individual host scanning
- **Port Enumeration**: Common port detection
- **Service Identification**: Basic service fingerprinting
- **Report Generation**: Text and CSV output formats

### 💻 Technical Foundation
- **Python 3.6+ Support**: Cross-platform compatibility
- **Threading**: Multi-threaded scanning for performance
- **Modular Design**: Extensible architecture
- **Error Handling**: Basic error management

---

## Version Numbering Scheme

PDIve follows semantic versioning (SemVer):
- **MAJOR.MINOR.PATCH** (e.g., 1.3.0)
- **MAJOR**: Breaking changes or major feature additions
- **MINOR**: New features, improvements, backward compatible
- **PATCH**: Bug fixes, documentation updates, minor improvements

## Development Branches

- **main**: Stable releases (v1.3.0, v1.2.0, etc.)
- **develop**: Development branch for upcoming features
- **feature/***: Feature development branches
- **hotfix/***: Critical bug fixes for stable releases

## Release Process

1. **Development**: Feature development in `develop` branch
2. **Testing**: Comprehensive testing of new features
3. **Documentation**: Update all relevant documentation
4. **Version Update**: Update version numbers in code and docs
5. **Release**: Merge to `main` and tag release
6. **Changelog**: Update CHANGELOG.md with release notes

## Upgrade Notes

### Upgrading from v1.2 to v1.3

**New Requirements:**
- No additional dependencies required
- Existing installations work unchanged

**New Features:**
- Automatic masscan sudo handling
- Enhanced error messages and troubleshooting
- Comprehensive documentation suite

**Configuration Changes:**
- Optional: Configure passwordless sudo for masscan
- Recommended: Review new INSTALL.md and USAGE.md guides

**Breaking Changes:**
- None - fully backward compatible

### Upgrading from v1.1 to v1.2

**Major Changes:**
- Project renamed from "Roverly" to "PDIve"
- Passive mode simplified to use only Amass
- Active mode enhanced with masscan integration

**Configuration Changes:**
- Install masscan for enhanced active scanning
- Update any scripts referencing "Roverly"

### Upgrading from v1.0 to v1.1

**New Requirements:**
- OWASP Amass installation required
- Additional Python dependencies (requests, urllib3)

**New Features:**
- Passive discovery mode
- Multiple OSINT source integration
- Enhanced reporting capabilities

## Contributing

When contributing to PDIve:

1. **Follow Semantic Versioning**: Increment versions appropriately
2. **Update Changelog**: Add entries for all changes
3. **Update Documentation**: Keep all docs current
4. **Test Thoroughly**: Ensure backward compatibility
5. **Security Review**: Consider security implications of changes

## Security Considerations by Version

### v1.3.0 Security Features
- Enhanced privilege management for masscan
- Clear sudo configuration guidance
- Improved error handling prevents information leakage

### v1.2.0 Security Features
- Streamlined tool integration reduces attack surface
- Better input validation and sanitization
- Enhanced authorization prompts

### v1.1.0 Security Features
- Passive discovery reduces network footprint
- Multiple verification sources for accuracy
- Rate limiting and respectful external API usage

### v1.0.0 Security Features
- Basic authorization prompts
- Safe default configurations
- Minimal network impact options

## Future Roadmap

### Planned for v1.4.0
- **Enhanced Service Detection**: Improved service fingerprinting
- **Custom Port Ranges**: User-defined port scanning ranges
- **Output Formats**: Additional report formats (JSON, XML)
- **Performance Improvements**: Optimized scanning algorithms

### Planned for v1.5.0
- **Database Integration**: Optional database storage for results
- **Web Interface**: Optional web-based interface
- **Plugin Architecture**: Extensible plugin system
- **Advanced Reporting**: Enhanced visualization and analysis

### Long-term Goals
- **Machine Learning**: AI-powered service detection
- **Cloud Integration**: Cloud-native deployment options
- **Enterprise Features**: Multi-user, role-based access control
- **API Interface**: RESTful API for integration

---

## Support and Maintenance

### Version Support Policy
- **Current Version (v1.3.x)**: Full support with bug fixes and security updates
- **Previous Major (v1.2.x)**: Security updates only
- **Legacy Versions (v1.1.x and older)**: No longer supported

### Reporting Issues
- **Security Issues**: Report privately to security team
- **Bug Reports**: Use GitHub issue tracker
- **Feature Requests**: Use GitHub discussions or issues
- **Documentation**: Include version number and environment details

### Getting Help
1. **Documentation**: Check README.md, INSTALL.md, USAGE.md
2. **Troubleshooting**: Review troubleshooting sections
3. **Community**: Search existing GitHub issues
4. **Support**: Create new issue with detailed information

---

*Last updated: 2025-09-25*
*Next scheduled review: 2025-12-25*