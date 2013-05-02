/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cloudstack.storage.image.store;

import javax.inject.Inject;

import org.apache.cloudstack.engine.subsystem.api.storage.DataObjectInStore;
import org.apache.cloudstack.engine.subsystem.api.storage.DataObjectType;
import org.apache.cloudstack.engine.subsystem.api.storage.DataStore;
import org.apache.cloudstack.engine.subsystem.api.storage.DataTO;
import org.apache.cloudstack.engine.subsystem.api.storage.ObjectInDataStoreStateMachine;
import org.apache.cloudstack.engine.subsystem.api.storage.ObjectInDataStoreStateMachine.Event;
import org.apache.cloudstack.engine.subsystem.api.storage.TemplateEvent;
import org.apache.cloudstack.engine.subsystem.api.storage.TemplateInfo;
import org.apache.cloudstack.engine.subsystem.api.storage.disktype.DiskFormat;
import org.apache.cloudstack.storage.command.CopyCmdAnswer;
import org.apache.cloudstack.storage.datastore.ObjectInDataStoreManager;
import org.apache.cloudstack.storage.datastore.db.TemplateDataStoreDao;
import org.apache.cloudstack.storage.datastore.db.TemplateDataStoreVO;
import org.apache.cloudstack.storage.image.manager.ImageDataManager;
import org.apache.cloudstack.storage.to.TemplateObjectTO;
import org.apache.log4j.Logger;

import com.cloud.agent.api.Answer;
import com.cloud.storage.DataStoreRole;
import com.cloud.storage.VMTemplateStoragePoolVO;
import com.cloud.storage.VMTemplateVO;
import com.cloud.storage.VMTemplateStorageResourceAssoc.Status;
import com.cloud.storage.dao.VMTemplateDao;
import com.cloud.storage.dao.VMTemplatePoolDao;
import com.cloud.utils.component.ComponentContext;
import com.cloud.utils.exception.CloudRuntimeException;
import com.cloud.utils.fsm.NoTransitionException;

public class TemplateObject implements TemplateInfo {
    private static final Logger s_logger = Logger
            .getLogger(TemplateObject.class);
    private VMTemplateVO imageVO;
    private DataStore dataStore;
    @Inject
    ImageDataManager imageMgr;
    @Inject
    VMTemplateDao imageDao;
    @Inject
    ObjectInDataStoreManager ojbectInStoreMgr;
    @Inject VMTemplatePoolDao templatePoolDao;
    @Inject TemplateDataStoreDao templateStoreDao;

    public TemplateObject() {
    }

    protected void configure(VMTemplateVO template, DataStore dataStore) {
        this.imageVO = template;
        this.dataStore = dataStore;
    }

    public static TemplateObject getTemplate(VMTemplateVO vo, DataStore store) {
        TemplateObject to = ComponentContext.inject(TemplateObject.class);
        to.configure(vo, store);
        return to;
    }


    public void setSize(Long size) {
        this.imageVO.setSize(size);
    }

    public VMTemplateVO getImage() {
        return this.imageVO;
    }

    @Override
    public DataStore getDataStore() {
        return this.dataStore;
    }

    @Override
    public String getUniqueName() {
        return this.imageVO.getUniqueName();
    }

    @Override
    public long getId() {
        return this.imageVO.getId();
    }

    @Override
    public String getUuid() {
        return this.imageVO.getUuid();
    }

    @Override
    public String getUri() {
        VMTemplateVO image = imageDao.findById(this.imageVO.getId());
       
            return image.getUrl();
       
    }

    @Override
    public Long getSize() {
        if (this.dataStore == null) {
            return this.imageVO.getSize();
        }

        /*

// If the template that was passed into this allocator is not installed in the storage pool,
            // add 3 * (template size on secondary storage) to the running total
            VMTemplateHostVO templateHostVO = _storageMgr.findVmTemplateHost(templateForVmCreation.getId(), null);

            if (templateHostVO == null) {
                VMTemplateSwiftVO templateSwiftVO = _swiftMgr.findByTmpltId(templateForVmCreation.getId());
                if (templateSwiftVO != null) {
                    long templateSize = templateSwiftVO.getPhysicalSize();
                    if (templateSize == 0) {
                        templateSize = templateSwiftVO.getSize();
                    }
                    totalAllocatedSize += (templateSize + _extraBytesPerVolume);
                }
            } else {
                long templateSize = templateHostVO.getPhysicalSize();
                if ( templateSize == 0 ){
                    templateSize = templateHostVO.getSize();
                }
                totalAllocatedSize +=  (templateSize + _extraBytesPerVolume);
            }

         */
        VMTemplateVO image = imageDao.findById(this.imageVO.getId());
        return image.getSize();
    }

    @Override
    public DataObjectType getType() {
        return DataObjectType.TEMPLATE;
    }

    @Override
    public DiskFormat getFormat() {
        return DiskFormat.valueOf(this.imageVO.getFormat().toString());
    }

    public boolean stateTransit(TemplateEvent e) throws NoTransitionException {
        boolean result= imageMgr.getStateMachine().transitTo(this.imageVO, e, null,
                imageDao);
        this.imageVO = imageDao.findById(this.imageVO.getId());
        return result;
    }

    @Override
    public void processEvent(Event event) {
        try {
            ojbectInStoreMgr.update(this, event);
        } catch (NoTransitionException e) {
            s_logger.debug("failed to update state", e);
            throw new CloudRuntimeException("Failed to update state" + e.toString());
        }
    }

    @Override
    public void processEvent(ObjectInDataStoreStateMachine.Event event, Answer answer) {
        try {
        	if (this.getDataStore().getRole() == DataStoreRole.Primary) {
        		if (answer instanceof CopyCmdAnswer) {
        			CopyCmdAnswer cpyAnswer = (CopyCmdAnswer)answer;
        			TemplateObjectTO newTemplate = (TemplateObjectTO)cpyAnswer.getNewData();
        			VMTemplateStoragePoolVO templatePoolRef = templatePoolDao.findByPoolTemplate(this.getDataStore().getId(), this.getId());
        			templatePoolRef.setDownloadPercent(100);
        			templatePoolRef.setDownloadState(Status.DOWNLOADED);
        			templatePoolRef.setLocalDownloadPath(newTemplate.getPath());
        			templatePoolRef.setInstallPath(newTemplate.getPath());
        			templatePoolDao.update(templatePoolRef.getId(), templatePoolRef);
        		}
        	} else if (this.getDataStore().getRole() == DataStoreRole.Image || 
        			this.getDataStore().getRole() == DataStoreRole.ImageCache) {
        		if (answer instanceof CopyCmdAnswer) {
        			CopyCmdAnswer cpyAnswer = (CopyCmdAnswer)answer;
        			TemplateObjectTO newTemplate = (TemplateObjectTO)cpyAnswer.getNewData();
        			TemplateDataStoreVO templateStoreRef = this.templateStoreDao.findByStoreTemplate(this.getDataStore().getId(),
        					this.getId());
        			templateStoreRef.setInstallPath(newTemplate.getPath());
        			templateStoreDao.update(templateStoreRef.getId(), templateStoreRef);
        		}
        	}
            ojbectInStoreMgr.update(this, event);
        } catch (NoTransitionException e) {
            s_logger.debug("failed to update state", e);
            throw new CloudRuntimeException("Failed to update state" + e.toString());
        }
    }

    @Override
    public DataTO getTO() {
        DataTO to = this.dataStore.getDriver().getTO(this);
        if (to == null) {
            to = new TemplateObjectTO(this);
        }

        return to;
    }

	@Override
	public String getInstallPath() {
		 DataObjectInStore obj = ojbectInStoreMgr.findObject(this, this.dataStore);
         return obj.getInstallPath();
	}
}
