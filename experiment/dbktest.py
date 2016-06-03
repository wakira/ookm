from mininet.topo import Topo
 
class DbkTest( Topo ):

    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")
        s5 = self.addSwitch("s5")
        s6 = self.addSwitch("s6")

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s5)
        self.addLink(s4, s5)
        self.addLink(s5, s6)

        # Host
        self.addLink(s1, self.addHost("h1"))
        self.addLink(s6, self.addHost("h2"))

topos = { 'dbktest': ( lambda: DbkTest() ) }
