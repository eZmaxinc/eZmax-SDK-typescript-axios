/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { EzsignfolderImportEzsignfoldersignerassociationsV1ResponseAllOf } from './ezsignfolder-import-ezsignfoldersignerassociations-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload } from './ezsignfolder-import-ezsignfoldersignerassociations-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignfolderImportEzsignfoldersignerassociationsV1Response
 * Response for POST /1/object/ezsignfolder/{pkiEzsignfolder}/importEzsignfoldersignerassociations
 * @export
 */
export type EzsignfolderImportEzsignfoldersignerassociationsV1Response = CommonResponse & EzsignfolderImportEzsignfoldersignerassociationsV1ResponseAllOf;


/**
 * @export 
 * A EzsignfolderImportEzsignfoldersignerassociationsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfolderImportEzsignfoldersignerassociationsV1Response
 */
export class DefaultObjectEzsignfolderImportEzsignfoldersignerassociationsV1Response extends DefaultObject {
   mPayload:Partial<EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


