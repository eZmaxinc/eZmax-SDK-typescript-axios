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
import type { EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload } from './ezsignfolder-import-ezsignfoldersignerassociations-v1-response-mpayload';

/**
 * @type EzsignfolderImportEzsignfoldersignerassociationsV1Response
 * Response for POST /1/object/ezsignfolder/{pkiEzsignfolder}/importEzsignfoldersignerassociations
 * @export
 */
/*export type EzsignfolderImportEzsignfoldersignerassociationsV1Response = CommonResponse;*/
export interface EzsignfolderImportEzsignfoldersignerassociationsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfolderImportEzsignfoldersignerassociationsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderImportEzsignfoldersignerassociationsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload}
     * @memberof EzsignfolderImportEzsignfoldersignerassociationsV1Response
     */
    mPayload:EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload 
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
import { DataObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderImportEzsignfoldersignerassociationsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderImportEzsignfoldersignerassociationsV1Response
 */
export class DataObjectEzsignfolderImportEzsignfoldersignerassociationsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload = new DataObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderImportEzsignfoldersignerassociationsV1Response Validation Object
 * @class ValidationObjectEzsignfolderImportEzsignfoldersignerassociationsV1Response
 */
export class ValidationObjectEzsignfolderImportEzsignfoldersignerassociationsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload()
} 


