# EzsignfolderResponse

An Ezsignfolder Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**objEzsignfoldertype** | [**CustomEzsignfoldertypeResponse**](CustomEzsignfoldertypeResponse.md) |  | [optional] [default to undefined]
**fkiTimezoneID** | **number** | The unique ID of the Timezone | [optional] [default to undefined]
**eEzsignfolderCompletion** | [**FieldEEzsignfolderCompletion**](FieldEEzsignfolderCompletion.md) |  | [default to undefined]
**sEzsignfoldertypeNameX** | **string** |  | [optional] [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [optional] [default to undefined]
**sBillingentityinternalDescriptionX** | **string** | The description of the Billingentityinternal in the language of the requester | [optional] [default to undefined]
**fkiEzsigntsarequirementID** | **number** | The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\&#39;s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\&#39;s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**| | [optional] [default to undefined]
**sEzsigntsarequirementDescriptionX** | **string** | The description of the Ezsigntsarequirement in the language of the requester | [optional] [default to undefined]
**sEzsignfolderDescription** | **string** | The description of the Ezsignfolder | [default to undefined]
**tEzsignfolderNote** | **string** | Note about the Ezsignfolder | [optional] [default to undefined]
**bEzsignfolderIsdisposable** | **boolean** | If the Ezsigndocument can be disposed | [optional] [default to undefined]
**eEzsignfolderSendreminderfrequency** | [**FieldEEzsignfolderSendreminderfrequency**](FieldEEzsignfolderSendreminderfrequency.md) |  | [optional] [default to undefined]
**iEzsignfolderSendreminderfirstdays** | **number** | The number of days before the the first reminder sending | [optional] [default to undefined]
**iEzsignfolderSendreminderotherdays** | **number** | The number of days after the first reminder sending | [optional] [default to undefined]
**dtEzsignfolderDelayedsenddate** | **string** | The date and time at which the Ezsignfolder will be sent in the future. | [optional] [default to undefined]
**dtEzsignfolderDuedate** | **string** | The maximum date and time at which the Ezsignfolder can be signed. | [optional] [default to undefined]
**dtEzsignfolderSentdate** | **string** | The date and time at which the Ezsignfolder was sent the last time. | [optional] [default to undefined]
**dtEzsignfolderScheduledarchive** | **string** | The scheduled date and time at which the Ezsignfolder should be archived. | [optional] [default to undefined]
**dtEzsignfolderScheduleddispose** | **string** | The scheduled date at which the Ezsignfolder should be Disposed. | [optional] [default to undefined]
**eEzsignfolderStep** | [**FieldEEzsignfolderStep**](FieldEEzsignfolderStep.md) |  | [optional] [default to undefined]
**eEzsignfolderMessageorder** | [**FieldEEzsignfolderMessageorder**](FieldEEzsignfolderMessageorder.md) |  | [optional] [default to undefined]
**dtEzsignfolderClose** | **string** | The date and time at which the Ezsignfolder was closed. Either by applying the last signature or by completing it prematurely. | [optional] [default to undefined]
**tEzsignfolderMessage** | **string** | A custom text message that will be added to the email sent. | [optional] [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [optional] [default to undefined]
**sEzsignfolderExternalid** | **string** | This field can be used to store an External ID from the client\&#39;s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format.  | [optional] [default to undefined]

## Example

```typescript
import { EzsignfolderResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfolderResponse = {
    pkiEzsignfolderID,
    fkiEzsignfoldertypeID,
    objEzsignfoldertype,
    fkiTimezoneID,
    eEzsignfolderCompletion,
    sEzsignfoldertypeNameX,
    fkiBillingentityinternalID,
    sBillingentityinternalDescriptionX,
    fkiEzsigntsarequirementID,
    sEzsigntsarequirementDescriptionX,
    sEzsignfolderDescription,
    tEzsignfolderNote,
    bEzsignfolderIsdisposable,
    eEzsignfolderSendreminderfrequency,
    iEzsignfolderSendreminderfirstdays,
    iEzsignfolderSendreminderotherdays,
    dtEzsignfolderDelayedsenddate,
    dtEzsignfolderDuedate,
    dtEzsignfolderSentdate,
    dtEzsignfolderScheduledarchive,
    dtEzsignfolderScheduleddispose,
    eEzsignfolderStep,
    eEzsignfolderMessageorder,
    dtEzsignfolderClose,
    tEzsignfolderMessage,
    objAudit,
    sEzsignfolderExternalid,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
