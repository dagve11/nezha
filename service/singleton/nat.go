package singleton

import (
	"cmp"
	"slices"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
)

type NATClass struct {
	class[uint16, *model.NAT]

	idToPort   map[uint64]uint16
	idToConfig map[uint64]*model.NAT
}

func NewNATClass() *NATClass {
	var sortedList []*model.NAT

	DB.Find(&sortedList)
	list := make(map[uint16]*model.NAT, len(sortedList))
	idToPort := make(map[uint64]uint16, len(sortedList))
	idToConfig := make(map[uint64]*model.NAT, len(sortedList))
	for _, profile := range sortedList {
		idToConfig[profile.ID] = profile
		if profile.Port != 0 {
			list[profile.Port] = profile
			idToPort[profile.ID] = profile.Port
		}
	}

	return &NATClass{
		class: class[uint16, *model.NAT]{
			list:       list,
			sortedList: sortedList,
		},
		idToPort:   idToPort,
		idToConfig: idToConfig,
	}
}

func (c *NATClass) Update(n *model.NAT) {
	c.listMu.Lock()

	if oldPort, ok := c.idToPort[n.ID]; ok && oldPort != n.Port {
		delete(c.list, oldPort)
	}

	c.idToConfig[n.ID] = n
	if n.Port != 0 {
		c.list[n.Port] = n
		c.idToPort[n.ID] = n.Port
	} else {
		delete(c.idToPort, n.ID)
	}

	c.listMu.Unlock()
	c.sortList()
}

func (c *NATClass) Delete(idList []uint64) {
	c.listMu.Lock()

	for _, id := range idList {
		if port, ok := c.idToPort[id]; ok {
			delete(c.list, port)
			delete(c.idToPort, id)
		}
		delete(c.idToConfig, id)
	}

	c.listMu.Unlock()
	c.sortList()
}

func (c *NATClass) GetNATConfigByPort(port uint16) *model.NAT {
	c.listMu.RLock()
	defer c.listMu.RUnlock()

	return c.list[port]
}

func (c *NATClass) GetNATConfigByID(id uint64) *model.NAT {
	c.listMu.RLock()
	defer c.listMu.RUnlock()

	return c.idToConfig[id]
}

func (c *NATClass) GetPort(id uint64) uint16 {
	c.listMu.RLock()
	defer c.listMu.RUnlock()

	return c.idToPort[id]
}

func (c *NATClass) sortList() {
	c.listMu.RLock()
	defer c.listMu.RUnlock()

	sortedList := utils.MapValuesToSlice(c.idToConfig)
	slices.SortFunc(sortedList, func(a, b *model.NAT) int {
		return cmp.Compare(a.ID, b.ID)
	})

	c.sortedListMu.Lock()
	defer c.sortedListMu.Unlock()
	c.sortedList = sortedList
}
