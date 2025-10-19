# FranchisereferalincomeRequestCompound

A Franchisereferalincome Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiFranchisereferalincomeID** | **number** | The unique ID of the Franchisereferalincome | [optional] [default to undefined]
**fkiFranchisebrokerID** | **number** | The unique ID of the Franchisebroker | [default to undefined]
**fkiFranchisereferalincomeprogramID** | **number** | The unique ID of the Franchisereferalincomeprogram | [default to undefined]
**fkiPeriodID** | **number** | The unique ID of the Period | [default to undefined]
**dFranchisereferalincomeLoan** | **string** | The loan amount | [default to undefined]
**dFranchisereferalincomeFranchiseamount** | **string** | The amount that will be given to the franchise | [default to undefined]
**dFranchisereferalincomeFranchisoramount** | **string** | The amount that will be kept by the franchisor | [default to undefined]
**dFranchisereferalincomeAgentamount** | **string** | The amount that will be given to the agent | [default to undefined]
**dtFranchisereferalincomeDisbursed** | **string** | The date the amounts were disbursed | [default to undefined]
**tFranchisereferalincomeComment** | **string** | Comment about the transaction | [default to undefined]
**fkiFranchiseofficeID** | **number** | The unique ID of the Franchisereoffice | [default to undefined]
**sFranchisereferalincomeRemoteid** | **string** |  | [default to undefined]
**objAddress** | [**AddressRequest**](AddressRequest.md) |  | [optional] [default to undefined]
**a_objContact** | [**Array&lt;ContactRequestCompound&gt;**](ContactRequestCompound.md) |  | [default to undefined]

## Example

```typescript
import { FranchisereferalincomeRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: FranchisereferalincomeRequestCompound = {
    pkiFranchisereferalincomeID,
    fkiFranchisebrokerID,
    fkiFranchisereferalincomeprogramID,
    fkiPeriodID,
    dFranchisereferalincomeLoan,
    dFranchisereferalincomeFranchiseamount,
    dFranchisereferalincomeFranchisoramount,
    dFranchisereferalincomeAgentamount,
    dtFranchisereferalincomeDisbursed,
    tFranchisereferalincomeComment,
    fkiFranchiseofficeID,
    sFranchisereferalincomeRemoteid,
    objAddress,
    a_objContact,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
