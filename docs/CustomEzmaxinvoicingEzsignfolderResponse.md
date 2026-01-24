# CustomEzmaxinvoicingEzsignfolderResponse

An EzmaxinvoicingEzsignfolder object containing information about the Ezmaxinvoicing for an Ezsignfolder

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [optional] [default to undefined]
**sEzsignfolderDescription** | **string** | The description of the Ezsignfolder | [default to undefined]
**bEzsigntsarequirementBillable** | **boolean** | Whether the TSA requirement is billable or not | [default to undefined]
**bEzsignfolderMfaused** | **boolean** | Whether the MFA was used or not for the Ezsignfolder | [default to undefined]
**bEzsignfolderAllowed** | **boolean** | Whether you have access to the Ezsignfolder or not | [default to undefined]

## Example

```typescript
import { CustomEzmaxinvoicingEzsignfolderResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzmaxinvoicingEzsignfolderResponse = {
    fkiEzsignfolderID,
    fkiBillingentityinternalID,
    sEzsignfolderDescription,
    bEzsigntsarequirementBillable,
    bEzsignfolderMfaused,
    bEzsignfolderAllowed,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
