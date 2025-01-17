/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfoldersignerassociationCreateObjectV2ResponseMPayload } from './ezsignfoldersignerassociation-create-object-v2-response-mpayload';

/**
 * @type EzsignfoldersignerassociationCreateObjectV2Response
 * Response for POST /2/object/ezsignfoldersignerassociation
 * @export
 */
/*export type EzsignfoldersignerassociationCreateObjectV2Response = CommonResponse;*/
export interface EzsignfoldersignerassociationCreateObjectV2Response {
    /**
     * 
     * @type {EzsignfoldersignerassociationCreateObjectV2ResponseMPayload}
     * @memberof EzsignfoldersignerassociationCreateObjectV2Response
     */
    mPayload:EzsignfoldersignerassociationCreateObjectV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationCreateObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationCreateObjectV2Response
 */
export class DataObjectEzsignfoldersignerassociationCreateObjectV2Response {
    mPayload:EzsignfoldersignerassociationCreateObjectV2ResponseMPayload = new DataObjectEzsignfoldersignerassociationCreateObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV2Response Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationCreateObjectV2Response
 */
export class ValidationObjectEzsignfoldersignerassociationCreateObjectV2Response {
   mPayload = new ValidationObjectEzsignfoldersignerassociationCreateObjectV2ResponseMPayload()
} 


