package exoscale

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/docker/machine/drivers"
	"github.com/docker/machine/ssh"
	"github.com/docker/machine/state"
	"github.com/pyr/egoscale/src/egoscale"
)

type Driver struct {
	URL              string
	ApiKey           string
	ApiSecretKey     string
	InstanceProfile  string
	DiskSize         int
	Image            string
	SecurityGroup    string
	AvailabilityZone string
	MachineName      string
	KeyPair          string

	IPAddress string
	PublicKey string
	Id        string

	storePath string
}

type CreateFlags struct {
	URL              *string
	ApiKey           *string
	ApiSecretKey     *string
	InstanceProfile  *string
	DiskSize         *int
	Image            *string
	SecurityGroup    *string
	AvailabilityZone *string
	MachineName      *string
	KeyPair          *string
}

func init() {
	drivers.Register("exoscale", &drivers.RegisteredDriver{
		New:            NewDriver,
		GetCreateFlags: GetCreateFlags,
	})
}

// RegisterCreateFlags registers the flags this driver adds to
// "docker hosts create"
func GetCreateFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "exosclae-url",
			EnvVar: "EXOSCALE_ENDPOINT",
			Usage:  "exoscale API endpoint",
		},
		cli.StringFlag{
			Name:   "exoscale-api-key",
			EnvVar: "EXOSCALE_API_KEY",
			Usage:  "exoscale API key",
		},
		cli.StringFlag{
			Name:   "exoscale-api-secret-key",
			EnvVar: "EXOSCALE_API_SECRET",
			Usage:  "exoscale API secret key",
		},
		cli.StringFlag{
			Name:  "exoscale-instance-profile",
			Value: "small",
			Usage: "exoscale instance profile (small, medium, large, ...)",
		},
		cli.IntFlag{
			Name:  "exoscale-disk-size",
			Value: 50,
			Usage: "exoscale disk size (10, 50, 100, 200, 400)",
		},
		cli.StringFlag{
			Name:  "exoscale-image",
			Value: "ubuntu-14.04",
			Usage: "exoscale image template",
		},
		cli.StringFlag{
			Name:  "exoscale-security-group",
			Value: "docker-machine",
			Usage: "exoscale security group",
		},
		cli.StringFlag{
			Name:  "exoscale-availability-zone",
			Value: "ch-gva-2",
			Usage: "exoscale availibility zone",
		},
		cli.StringFlag{
			Name:  "exoscale-machinename",
			Usage: "exoscale host name",
		},
		cli.StringFlag{
			Name:  "exoscale-keypair",
			Usage: "exoscale keypair name",
		},
	}
}

func NewDriver(storePath string) (drivers.Driver, error) {
	return &Driver{storePath: storePath}, nil
}

func (d *Driver) DriverName() string {
	return "exoscale"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.URL = flags.String("exoscale-endpoint")
	d.ApiKey = flags.String("exoscale-api-key")
	d.ApiSecretKey = flags.String("exoscale-api-secret-key")
	d.InstanceProfile = flags.String("exoscale-instance-profile")
	d.DiskSize = flags.Int("exoscale-disk-size")
	d.Image = flags.String("exoscale-image")
	d.SecurityGroup = flags.String("exoscale-security-group")
	d.AvailabilityZone = flags.String("exoscale-availability-zone")
	d.MachineName = flags.String("exoscale-machinename")
	d.KeyPair = flags.String("exoscale-keypair")

	if d.URL == "" {
		d.URL = "https://api.exoscale.ch/compute"
	}
	if d.MachineName == "" {
		rand.Seed(time.Now().UnixNano())
		d.MachineName = fmt.Sprintf("docker-host-%04x",
			rand.Intn(65535))
	}

	if d.ApiKey == "" || d.ApiSecretKey == "" {
		return fmt.Errorf("Please specify an API key (--exoscale-api-key) and an API secret key (--exoscale-api-secret-key).")
	}

	return nil
}

func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:2376", ip), nil
}

func (d *Driver) GetIP() (string, error) {
	if d.IPAddress == "" {
		return "", fmt.Errorf("IP address is not set.")
	}
	return d.IPAddress, nil
}

func (d *Driver) GetState() (state.State, error) {
	client := egoscale.NewClient(d.URL, d.ApiKey, d.ApiSecretKey)
	vm, err := client.GetVirtualMachine(d.Id)
	if err != nil {
		return state.Error, err
	}
	switch vm.State {
	case "Starting":
		return state.Starting, nil
	case "Running":
		return state.Running, nil
	case "Stopping":
		return state.Running, nil
	case "Stopped":
		return state.Stopped, nil
	case "Destroyed":
		return state.Stopped, nil
	case "Expunging":
		return state.Stopped, nil
	case "Migrating":
		return state.Paused, nil
	case "Error":
		return state.Error, nil
	case "Unknown":
		return state.Error, nil
	case "Shutdowned":
		return state.Stopped, nil
	}
	return state.None, nil
}

func (d *Driver) Create() error {
	log.Infof("Querying exoscale for the requested parameters...")
	client := egoscale.NewClient(d.URL, d.ApiKey, d.ApiSecretKey)
	topology, err := client.GetTopology()
	if err != nil {
		return err
	}

	// Availability zone UUID
	zone, ok := topology.Zones[d.AvailabilityZone]
	if !ok {
		return fmt.Errorf("Availability zone %v doesn't exist",
			d.AvailabilityZone)
	}
	log.Debugf("Availability zone %v = %s", d.AvailabilityZone, zone)

	// Image UUID
	var tpl string
	images, ok := topology.Images[strings.ToLower(d.Image)]
	if ok {
		tpl, ok = images[d.DiskSize]
	}
	if !ok {
		return fmt.Errorf("Unable to find image %v with size %d",
			d.Image, d.DiskSize)
	}
	log.Debugf("Image %v(%d) = %s", d.Image, d.DiskSize, tpl)

	// Profile UUID
	profile, ok := topology.Profiles[strings.ToLower(d.InstanceProfile)]
	if !ok {
		return fmt.Errorf("Unable to find the %s profile",
			d.InstanceProfile)
	}
	log.Debugf("Profile %v = %s", d.InstanceProfile, profile)

	// Security group
	sg, ok := topology.SecurityGroups[d.SecurityGroup]
	if !ok {
		log.Infof("Security group %v does not exist, create it",
			d.SecurityGroup)
		rules := []egoscale.SecurityGroupRule{
			{
				SecurityGroupId: "",
				Cidr:            "0.0.0.0/0",
				Protocol:        "TCP",
				Port:            22,
			},
			{
				SecurityGroupId: "",
				Cidr:            "0.0.0.0/0",
				Protocol:        "TCP",
				Port:            2376,
			},
			{
				SecurityGroupId: "",
				Cidr:            "0.0.0.0/0",
				Protocol:        "ICMP",
				IcmpType:        8,
				IcmpCode:        0,
			},
		}
		sgresp, err := client.CreateSecurityGroupWithRules(d.SecurityGroup,
			rules,
			make([]egoscale.SecurityGroupRule, 0, 0))
		if err != nil {
			return err
		}
		sg = sgresp.Id
	}
	log.Debugf("Security group %v = %s", d.SecurityGroup, sg)

	if d.KeyPair == "" {
		log.Infof("Generate an SSH keypair...")
		kpresp, err := client.CreateKeypair(d.MachineName)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(d.sshKeyPath(), []byte(kpresp.Privatekey), 0600)
		if err != nil {
			return err
		}
		d.KeyPair = d.MachineName
	}

	log.Infof("Spawn exoscale host...")

	userdata, err := d.getCloudInit()
	if err != nil {
		return err
	}
	log.Debugf("Using the following cloud-init file:")
	log.Debugf("%s", userdata)

	machineProfile := egoscale.MachineProfile{
		Template:        tpl,
		ServiceOffering: profile,
		SecurityGroups:  []string{sg},
		Userdata:        userdata,
		Zone:            zone,
		Keypair:         d.KeyPair,
		Name:            d.MachineName,
	}

	cvmresp, err := client.CreateVirtualMachine(machineProfile)
	if err != nil {
		return err
	}

	vm, err := d.waitForVM(client, cvmresp)
	if err != nil {
		return err
	}
	d.IPAddress = vm.Nic[0].Ipaddress
	d.Id = vm.Id
	err = d.waitForDocker()
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) Start() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}
	if vmstate == state.Running || vmstate == state.Starting {
		log.Infof("Host is already running or starting")
		return nil
	}

	client := egoscale.NewClient(d.URL, d.ApiKey, d.ApiSecretKey)
	svmresp, err := client.StartVirtualMachine(d.Id)
	if err != nil {
		return err
	}
	_, err = d.waitForVM(client, svmresp)
	if err != nil {
		return err
	}
	err = d.waitForDocker()
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Stop() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}
	if vmstate == state.Stopped {
		log.Infof("Host is already stopped")
		return nil
	}

	client := egoscale.NewClient(d.URL, d.ApiKey, d.ApiSecretKey)
	svmresp, err := client.StopVirtualMachine(d.Id)
	if err != nil {
		return err
	}
	_, err = d.waitForVM(client, svmresp)
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Remove() error {
	client := egoscale.NewClient(d.URL, d.ApiKey, d.ApiSecretKey)
	dvmresp, err := client.DestroyVirtualMachine(d.Id)
	if err != nil {
		return err
	}
	_, err = d.waitForVM(client, dvmresp)
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Restart() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}
	if vmstate == state.Stopped {
		return fmt.Errorf("Host is stopped, use start command to start it")
	}

	client := egoscale.NewClient(d.URL, d.ApiKey, d.ApiSecretKey)
	svmresp, err := client.RebootVirtualMachine(d.Id)
	if err != nil {
		return err
	}
	_, err = d.waitForVM(client, svmresp)
	if err != nil {
		return err
	}
	err = d.waitForDocker()
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) Upgrade() error {
	sshCmd, err := d.GetSSHCommand("sudo apt-get update && sudo apt-get install lxc-docker")
	if err != nil {
		return err
	}
	sshCmd.Stdin = os.Stdin
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	if err := sshCmd.Run(); err != nil {
		return fmt.Errorf("%s", err)
	}
	return nil
}

func (driver *Driver) GetSSHCommand(args ...string) (*exec.Cmd, error) {
	vmstate, err := driver.GetState()
	if err != nil {
		return nil, err
	}

	if vmstate == state.Stopped {
		return nil, fmt.Errorf("Host is stopped. Please start it before using ssh command.")
	}

	return ssh.GetSSHCommand(driver.IPAddress, 22, "ubuntu", driver.sshKeyPath(), args...), nil
}

func (d *Driver) waitForDocker() error {
	log.Infof("Waiting for docker daemon on host to be available...")
	maxRepeats := 48
	url, err := d.GetURL()
	if err != nil {
		return err
	}
	components := strings.SplitN(url, "://", 2)
	protocol, host := components[0], components[1]
	i := 0
	for ; i < maxRepeats; i++ {
		conn, err := net.Dial(protocol, host)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if i == maxRepeats {
		return fmt.Errorf("Cannot run docker daemon on remote machine")
	}
	return nil
}

func (d *Driver) waitForVM(client *egoscale.Client, jobid string) (*egoscale.DeployVirtualMachineResponse, error) {
	log.Infof("Waiting for VM...")
	maxRepeats := 60
	i := 0
	var resp *egoscale.QueryAsyncJobResultResponse
	var err error
	for ; i < maxRepeats; i++ {
		resp, err = client.PollAsyncJob(jobid)
		if err != nil {
			return nil, err
		}

		if resp.Jobstatus == 1 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if i == maxRepeats {
		return nil, fmt.Errorf("Timeout while waiting for VM")
	}
	vm, err := client.AsyncToVirtualMachine(*resp)
	if err != nil {
		return nil, err
	}

	return vm, nil
}

// Build a cloud-init user data string that will install and run
// docker.
func (d *Driver) getCloudInit() (string, error) {
	const tpl = `#cloud-config
manage_etc_hosts: true
fqdn: {{ .MachineName }}
resize_rootfs: true

apt_sources:
  - source: "deb https://get.docker.com/ubuntu docker main"
    filename: docker.list
    key: |
      -----BEGIN PGP PUBLIC KEY BLOCK-----
      Version: GnuPG v1
      
      mQENBFIOqEUBCADsvqwefcPPQArws9jHF1PaqhXxkaXzeE5uHHtefdoRxQdjoGok
      HFmHWtCd9zR7hDpHE7Q4dwJtSFWZAM3zaUtlvRAgvMmfLm08NW9QQn0CP5khjjF1
      cgckhjmzQAzpEHO5jiSwl0ZU8ouJrLDgmbhT6knB1XW5/VmeECqKRyhlEK0zRz1a
      XV+4EVDySlORmFyqlmdIUmiU1/6pKEXyRBBVCHNsbnpZOOzgNhfMz8VE8Hxq7Oh8
      1qFaFXjNGCrNZ6xr/DI+iXlsZ8urlZjke5llm4874N8VPUeFQ/szmsbSqmCnbd15
      LLtrpvpSMeyRG+LoTYvyTG9QtAuewL9EKJPfABEBAAG0OURvY2tlciBSZWxlYXNl
      IFRvb2wgKHJlbGVhc2Vkb2NrZXIpIDxkb2NrZXJAZG90Y2xvdWQuY29tPokBOAQT
      AQIAIgUCUg6oRQIbLwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQ2Fdqi6iN
      IenM+QgAnOiozhHDAYGO92SmZjib6PK/1djbrDRMreCT8bnzVpriTOlEtARDXsmX
      njKSFa+HTxHi/aTNo29TmtHDfUupcfmaI2mXbZt1ixXLuwcMv9sJXKoeWwKZnN3i
      9vAM9/yAJz3aq+sTXeG2dDrhZr34B3nPhecNkKQ4v6pnQy43Mr59Fvv5CzKFa9oZ
      IoZf+Ul0F90HSw5WJ1NsDdHGrAaHLZfzqAVrqHzazw7ghe94k460T8ZAaovCaTQV
      HzTcMfJdPz/uTim6J0OergT9njhtdg2ugUj7cPFUTpsxQ1i2S8qDEQPL7kabAZZo
      Pim0BXdjsHVftivqZqfWeVFKMorchQ==
      =fRgo
      -----END PGP PUBLIC KEY BLOCK-----

packages:
 - lxc-docker
write_files:
 - path: /etc/default/docker
   owner: root:root
   permissions: '0644'
   content: |
     # Docker Upstart and SysVinit configuration file
     DOCKER_OPTS="--auth=identity --host=tcp://0.0.0.0:2376"
 - path: /.docker/authorized-keys.d/docker-host.json
   owner: root:root
   permissions: '0644'
   content: |
     {{ .PublicKey }}
# Current hack until identity auth is merged in docker
runcmd:
 - stop docker
 - curl -sS https://bfirsh.s3.amazonaws.com/docker/docker-1.3.1-dev-identity-auth > /usr/bin/docker
 - start docker
`
	var buffer bytes.Buffer

	d.setPublicKey()
	tmpl, err := template.New("cloud-init").Parse(tpl)
	if err != nil {
		return "", err
	}
	err = tmpl.Execute(&buffer, d)
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func (d *Driver) setPublicKey() error {
	f, err := os.Open(drivers.PublicKeyPath())
	if err != nil {
		return err
	}
	defer f.Close()
	key, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	// A bit hackish
	d.PublicKey = strings.Join(strings.Split(string(key), "\n"), "\n     ")
	return nil
}

func (d *Driver) sshKeyPath() string {
	return filepath.Join(d.storePath, "id_rsa")
}
