/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
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

import { DefaultObject } from '../base'

/**
 * @type EzsignfolderDisposeEzsignfoldersV1Response
 * Response for POST /1/object/ezsignfolder/disposeEzsignfolders
 * @export
 */
export type EzsignfolderDisposeEzsignfoldersV1Response = CommonResponse;


/**
 * @export 
 * A EzsignfolderDisposeEzsignfoldersV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfolderDisposeEzsignfoldersV1Response
 */
export class DefaultObjectEzsignfolderDisposeEzsignfoldersV1Response extends DefaultObject {
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


