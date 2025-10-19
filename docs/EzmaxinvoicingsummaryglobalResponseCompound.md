# EzmaxinvoicingsummaryglobalResponseCompound

A Ezmaxinvoicingsummaryglobal Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzmaxinvoicingsummaryglobalID** | **number** | The unique ID of the Ezmaxinvoicingsummaryglobal | [optional] [default to undefined]
**fkiEzmaxinvoicingID** | **number** | The unique ID of the Ezmaxinvoicing | [optional] [default to undefined]
**fkiEzmaxproductID** | **number** | The unique ID of the Ezmaxproduct | [default to undefined]
**sEzmaxproductDescriptionX** | **string** | The description of the Ezmaxproduct in the language of the requester | [default to undefined]
**dtEzmaxinvoicingsummaryglobalStart** | **string** | The start date for the Ezmaxinvoicingsummaryglobal | [default to undefined]
**dtEzmaxinvoicingsummaryglobalEnd** | **string** | The end date for the Ezmaxinvoicingsummaryglobal | [default to undefined]
**iEzmaxinvoicingsummaryglobalDays** | **number** | The number of days for the Ezmaxinvoicingsummaryglobal | [default to undefined]
**dEzmaxinvoicingsummaryglobalCountreal** | **string** | The count item calculated | [default to undefined]
**dEzmaxinvoicingsummaryglobalCountbilled** | **string** | The count item billed | [default to undefined]
**dEzmaxinvoicingsummaryglobalSubtotal** | **string** | The Ezmaxinvoicingsummaryglobal subtotal | [default to undefined]
**dEzmaxinvoicingsummaryglobalRebateamount** | **string** | The rebate amount for the Ezmaxinvoicingsummaryglobal | [default to undefined]
**dEzmaxinvoicingsummaryglobalRebatepercent** | **string** | The rebate percentage of the Ezmaxinvoicingsummaryglobal | [default to undefined]
**dEzmaxinvoicingsummaryglobalRebatetotal** | **string** | The rebate amount total for the Ezmaxinvoicingsummaryglobal | [default to undefined]
**dEzmaxinvoicingsummaryglobalTotal** | **string** | The Ezmaxinvoicingsummaryglobal total | [default to undefined]
**dEzmaxinvoicingsummaryglobalRepresentative** | **string** | The amount of commission for the representative | [optional] [default to undefined]
**dEzmaxinvoicingsummaryglobalPartner** | **string** | The amount of commission for the partner | [optional] [default to undefined]
**dEzmaxinvoicingsummaryglobalNet** | **string** | The net amount of the Ezmaxinvoicingsummaryglobal | [optional] [default to undefined]
**bEzmaxinvoicingsummaryglobalAdjustment** | **boolean** | Whether it is adjustment for the Ezmaxinvoicingsummaryglobal | [default to undefined]
**tEzmaxproductHelpX** | **string** | The help message of the Ezmaxproduct in the language of the requester | [default to undefined]
**a_objEzmaxinvoicingcommission** | [**Array&lt;EzmaxinvoicingcommissionResponseCompound&gt;**](EzmaxinvoicingcommissionResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzmaxinvoicingsummaryglobalResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzmaxinvoicingsummaryglobalResponseCompound = {
    pkiEzmaxinvoicingsummaryglobalID,
    fkiEzmaxinvoicingID,
    fkiEzmaxproductID,
    sEzmaxproductDescriptionX,
    dtEzmaxinvoicingsummaryglobalStart,
    dtEzmaxinvoicingsummaryglobalEnd,
    iEzmaxinvoicingsummaryglobalDays,
    dEzmaxinvoicingsummaryglobalCountreal,
    dEzmaxinvoicingsummaryglobalCountbilled,
    dEzmaxinvoicingsummaryglobalSubtotal,
    dEzmaxinvoicingsummaryglobalRebateamount,
    dEzmaxinvoicingsummaryglobalRebatepercent,
    dEzmaxinvoicingsummaryglobalRebatetotal,
    dEzmaxinvoicingsummaryglobalTotal,
    dEzmaxinvoicingsummaryglobalRepresentative,
    dEzmaxinvoicingsummaryglobalPartner,
    dEzmaxinvoicingsummaryglobalNet,
    bEzmaxinvoicingsummaryglobalAdjustment,
    tEzmaxproductHelpX,
    a_objEzmaxinvoicingcommission,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
