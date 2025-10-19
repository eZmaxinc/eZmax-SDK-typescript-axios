# CustomerRequest

A Customer Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCustomerID** | **number** | The unique ID of the Customer. | [optional] [default to undefined]
**fkiCompanyID** | **number** | The unique ID of the Company | [default to undefined]
**fkiCustomergroupID** | **number** | The unique ID of the Customergroup | [default to undefined]
**sCustomerName** | **string** | The name of the Customer | [default to undefined]
**sCustomerNote** | **string** | A note for the Customer | [optional] [default to undefined]
**fkiContactinformationsID** | **number** | The unique ID of the Contactinformations | [default to undefined]
**fkiContactcontainerID** | **number** | The unique ID of the Contactcontainer | [default to undefined]
**fkiImageID** | **number** | The unique ID of the Image | [default to undefined]
**fkiGlaccountcontainerID** | **number** | The unique ID of the Glaccountcontainer | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [default to undefined]
**fkiPaymentmethodID** | **number** | The unique ID of the Paymentmethod | [default to undefined]
**fkiElectronicfundstransferbankaccountID** | **number** | The unique ID of the Electronicfundstransferbankaccount | [default to undefined]
**fkiElectronicfundstransferbankaccountIDDirectdebit** | **number** | The unique ID of the Electronicfundstransferbankaccount | [default to undefined]
**fkiSendingmethodID** | **number** | The unique ID of the Sendingmethod | [default to undefined]
**fkiTaxassignmentID** | **number** | The unique ID of the Taxassignment.  Valid values:  |Value|Description| |-|-| |1|No tax| |2|GST| |3|HST (ON)| |4|HST (NB)| |5|HST (NS)| |6|HST (NL)| |7|HST (PE)| |8|GST + QST (QC)| |9|GST + QST (QC) Non-Recoverable| |10|GST + PST (BC)| |11|GST + PST (SK)| |12|GST + RST (MB)| |13|GST + PST (BC) Non-Recoverable| |14|GST + PST (SK) Non-Recoverable| |15|GST + RST (MB) Non-Recoverable| | [default to undefined]
**fkiAttendancestatusID** | **number** | The unique ID of the Attendancestatus | [default to undefined]
**fkiAgentIDVariableexpensechargeto** | **number** | The unique ID of the Agent. | [default to undefined]
**fkiBrokerIDVariableexpensechargeto** | **number** | The unique ID of the Broker. | [default to undefined]
**fkiCustomerIDVariableexpensechargeto** | **number** | The unique ID of the Customer. | [default to undefined]
**fkiGlaccountcontainerIDVariableexpensechargeto** | **number** | The unique ID of the Glaccountcontainer | [default to undefined]
**fkiAgentIDSupplychargechargeto** | **number** | The unique ID of the Agent. | [default to undefined]
**fkiBrokerIDSupplychargechargeto** | **number** | The unique ID of the Broker. | [default to undefined]
**fkiCustomerIDSupplychargechargeto** | **number** | The unique ID of the Customer. | [default to undefined]
**fkiGlaccountcontainerIDSupplychargechargeto** | **number** | The unique ID of the Glaccountcontainer | [default to undefined]
**fkiInvoicealternatelogoID** | **number** | The unique ID of the Invoicealternatelogo | [default to undefined]
**fkiSynchronizationlinkserverID** | **number** | The unique ID of the Synchronizationlinkserver | [default to undefined]
**efkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**efksCustomerCode** | **string** | The code of the Customer | [optional] [default to undefined]
**sCustomerCode** | **string** | The code of the Customer | [default to undefined]
**dCustomerFulltimeequivalent** | **string** | The fulltimeequivalent of the Customer | [default to undefined]
**iCustomerPhotocopiercode** | **number** | The photocopiercode of the Customer | [default to undefined]
**iCustomerLongdistancecode** | **number** | The longdistancecode of the Customer | [default to undefined]
**iCustomerTimewindowstart** | **number** | The timewindowstart of the Customer | [default to undefined]
**iCustomerTimewindowend** | **number** | The timewindowend of the Customer | [default to undefined]
**dCustomerMinimumchargeableinterests** | **string** | The minimumchargeableinterests of the Customer | [default to undefined]
**dtCustomerBirthdate** | **string** | The birthdate of the Customer | [default to undefined]
**dtCustomerTransfer** | **string** | The transfer of the Customer | [default to undefined]
**dtCustomerTransferappointment** | **string** | The transferappointment of the Customer | [default to undefined]
**dtCustomerTransfersurvey** | **string** | The transfersurvey of the Customer | [default to undefined]
**bCustomerIsactive** | **boolean** | Whether the customer is active or not | [default to undefined]
**bCustomerVariableexpensefinanced** | **boolean** | Whether if it\&#39;s an variableexpensefinanced | [default to undefined]
**bCustomerVariableexpensefinancedtaxes** | **boolean** | Whether if it\&#39;s an variableexpensefinancedtaxes | [default to undefined]
**bCustomerSupplychargefinanced** | **boolean** | Whether if it\&#39;s an supplychargefinanced | [default to undefined]
**bCustomerSupplychargefinancedtaxes** | **boolean** | Whether if it\&#39;s an supplychargefinancedtaxes | [default to undefined]
**bCustomerAttendance** | **boolean** | Whether if it\&#39;s an attendance | [default to undefined]
**eCustomerType** | [**FieldECustomerType**](FieldECustomerType.md) |  | [default to undefined]
**eCustomerMarketingcorrespondence** | [**FieldECustomerMarketingcorrespondence**](FieldECustomerMarketingcorrespondence.md) |  | [default to undefined]
**bCustomerBlackcopycarbon** | **boolean** | Whether if it\&#39;s an blackcopycarbon | [default to undefined]
**bCustomerUnsubscribeinfo** | **boolean** | Whether if it\&#39;s an unsubscribeinfo | [default to undefined]
**tCustomerComment** | **string** | The comment of the Customer | [default to undefined]
**IMPORTID** | **string** |  | [optional] [default to undefined]

## Example

```typescript
import { CustomerRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomerRequest = {
    pkiCustomerID,
    fkiCompanyID,
    fkiCustomergroupID,
    sCustomerName,
    sCustomerNote,
    fkiContactinformationsID,
    fkiContactcontainerID,
    fkiImageID,
    fkiGlaccountcontainerID,
    fkiLanguageID,
    fkiDepartmentID,
    fkiPaymentmethodID,
    fkiElectronicfundstransferbankaccountID,
    fkiElectronicfundstransferbankaccountIDDirectdebit,
    fkiSendingmethodID,
    fkiTaxassignmentID,
    fkiAttendancestatusID,
    fkiAgentIDVariableexpensechargeto,
    fkiBrokerIDVariableexpensechargeto,
    fkiCustomerIDVariableexpensechargeto,
    fkiGlaccountcontainerIDVariableexpensechargeto,
    fkiAgentIDSupplychargechargeto,
    fkiBrokerIDSupplychargechargeto,
    fkiCustomerIDSupplychargechargeto,
    fkiGlaccountcontainerIDSupplychargechargeto,
    fkiInvoicealternatelogoID,
    fkiSynchronizationlinkserverID,
    efkiUserID,
    efksCustomerCode,
    sCustomerCode,
    dCustomerFulltimeequivalent,
    iCustomerPhotocopiercode,
    iCustomerLongdistancecode,
    iCustomerTimewindowstart,
    iCustomerTimewindowend,
    dCustomerMinimumchargeableinterests,
    dtCustomerBirthdate,
    dtCustomerTransfer,
    dtCustomerTransferappointment,
    dtCustomerTransfersurvey,
    bCustomerIsactive,
    bCustomerVariableexpensefinanced,
    bCustomerVariableexpensefinancedtaxes,
    bCustomerSupplychargefinanced,
    bCustomerSupplychargefinancedtaxes,
    bCustomerAttendance,
    eCustomerType,
    eCustomerMarketingcorrespondence,
    bCustomerBlackcopycarbon,
    bCustomerUnsubscribeinfo,
    tCustomerComment,
    IMPORTID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
