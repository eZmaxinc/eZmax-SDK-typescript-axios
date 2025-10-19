# ObjectFranchisereferalincomeApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**franchisereferalincomeCreateObjectV2**](#franchisereferalincomecreateobjectv2) | **POST** /2/object/franchisereferalincome | Create a new Franchisereferalincome|

# **franchisereferalincomeCreateObjectV2**
> FranchisereferalincomeCreateObjectV2Response franchisereferalincomeCreateObjectV2(franchisereferalincomeCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectFranchisereferalincomeApi,
    Configuration,
    FranchisereferalincomeCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectFranchisereferalincomeApi(configuration);

let franchisereferalincomeCreateObjectV2Request: FranchisereferalincomeCreateObjectV2Request; //

const { status, data } = await apiInstance.franchisereferalincomeCreateObjectV2(
    franchisereferalincomeCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **franchisereferalincomeCreateObjectV2Request** | **FranchisereferalincomeCreateObjectV2Request**|  | |


### Return type

**FranchisereferalincomeCreateObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of this Franchisebroker is not in this Franchiseoffice. fkiFranchiseofficeID contains the id of Franchiseoffice where the Franchisebroker is located on the dtFranchisereferalincomeDisbursed.  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

