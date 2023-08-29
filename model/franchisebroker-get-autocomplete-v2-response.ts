/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { FranchisebrokerGetAutocompleteV2ResponseMPayload } from './franchisebroker-get-autocomplete-v2-response-mpayload';

/**
 * @type FranchisebrokerGetAutocompleteV2Response
 * Response for GET /2/object/franchisebroker/getAutocomplete
 * @export
 */
export type FranchisebrokerGetAutocompleteV2Response = CommonResponse;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectFranchisebrokerGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectFranchisebrokerGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A FranchisebrokerGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFranchisebrokerGetAutocompleteV2Response
 */
export class DataObjectFranchisebrokerGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:FranchisebrokerGetAutocompleteV2ResponseMPayload = new DataObjectFranchisebrokerGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A FranchisebrokerGetAutocompleteV2Response Validation Object
 * @class ValidationObjectFranchisebrokerGetAutocompleteV2Response
 */
export class ValidationObjectFranchisebrokerGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectFranchisebrokerGetAutocompleteV2ResponseMPayload()
} 


