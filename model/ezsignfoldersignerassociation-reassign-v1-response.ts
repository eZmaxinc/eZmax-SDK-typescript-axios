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

/**
 * @type EzsignfoldersignerassociationReassignV1Response
 * Response for GET /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/reassign
 * @export
 */
/*export type EzsignfoldersignerassociationReassignV1Response = CommonResponse;*/
export interface EzsignfoldersignerassociationReassignV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfoldersignerassociationReassignV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfoldersignerassociationReassignV1Response
     */
    objDebug?:CommonResponseObjDebug 
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
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationReassignV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationReassignV1Response
 */
export class DataObjectEzsignfoldersignerassociationReassignV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignfoldersignerassociationReassignV1Response Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationReassignV1Response
 */
export class ValidationObjectEzsignfoldersignerassociationReassignV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


