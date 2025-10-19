# ObjectModulegroupApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**modulegroupGetAllV1**](#modulegroupgetallv1) | **GET** /1/object/modulegroup/getAll/{eContext} | Retrieve all Modulegroups|

# **modulegroupGetAllV1**
> ModulegroupGetAllV1Response modulegroupGetAllV1()


### Example

```typescript
import {
    ObjectModulegroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectModulegroupApi(configuration);

let eContext: 'Api' | 'User'; //The context of the Modulegroup (default to undefined)

const { status, data } = await apiInstance.modulegroupGetAllV1(
    eContext
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eContext** | [**&#39;Api&#39; | &#39;User&#39;**]**Array<&#39;Api&#39; &#124; &#39;User&#39;>** | The context of the Modulegroup | defaults to undefined|


### Return type

**ModulegroupGetAllV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

