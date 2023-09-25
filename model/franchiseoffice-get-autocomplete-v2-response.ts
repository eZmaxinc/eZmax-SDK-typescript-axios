/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
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
import { FranchiseofficeGetAutocompleteV2ResponseMPayload } from './franchiseoffice-get-autocomplete-v2-response-mpayload';

/**
 * @type FranchiseofficeGetAutocompleteV2Response
 * Response for GET /2/object/franchiseoffice/getAutocomplete
 * @export
 */
/** export type FranchiseofficeGetAutocompleteV2Response = CommonResponse; */
export interface FranchiseofficeGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof FranchiseofficeGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof FranchiseofficeGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {FranchiseofficeGetAutocompleteV2ResponseMPayload}
     * @memberof FranchiseofficeGetAutocompleteV2Response
     */
    mPayload:FranchiseofficeGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectFranchiseofficeGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectFranchiseofficeGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A FranchiseofficeGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFranchiseofficeGetAutocompleteV2Response
 */
export class DataObjectFranchiseofficeGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:FranchiseofficeGetAutocompleteV2ResponseMPayload = new DataObjectFranchiseofficeGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A FranchiseofficeGetAutocompleteV2Response Validation Object
 * @class ValidationObjectFranchiseofficeGetAutocompleteV2Response
 */
export class ValidationObjectFranchiseofficeGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectFranchiseofficeGetAutocompleteV2ResponseMPayload()
} 


