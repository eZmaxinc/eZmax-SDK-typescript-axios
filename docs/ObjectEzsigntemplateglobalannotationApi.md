# ObjectEzsigntemplateglobalannotationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplateglobalannotationGetObjectV2**](#ezsigntemplateglobalannotationgetobjectv2) | **GET** /2/object/ezsigntemplateglobalannotation/{pkiEzsigntemplateglobalannotationID} | Retrieve an existing Ezsigntemplateglobalannotation|

# **ezsigntemplateglobalannotationGetObjectV2**
> EzsigntemplateglobalannotationGetObjectV2Response ezsigntemplateglobalannotationGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplateglobalannotationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateglobalannotationApi(configuration);

let pkiEzsigntemplateglobalannotationID: number; //The unique ID of the Ezsigntemplateglobalannotation (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateglobalannotationGetObjectV2(
    pkiEzsigntemplateglobalannotationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplateglobalannotationID** | [**number**] | The unique ID of the Ezsigntemplateglobalannotation | defaults to undefined|


### Return type

**EzsigntemplateglobalannotationGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

