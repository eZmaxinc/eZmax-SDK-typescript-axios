/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
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
import { EzsignfoldersignerassociationCreateObjectV2ResponseAllOf } from './ezsignfoldersignerassociation-create-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationCreateObjectV2ResponseMPayload } from './ezsignfoldersignerassociation-create-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignfoldersignerassociationCreateObjectV2Response
 * Response for POST /2/object/ezsignfoldersignerassociation
 * @export
 */
export type EzsignfoldersignerassociationCreateObjectV2Response = CommonResponse & EzsignfoldersignerassociationCreateObjectV2ResponseAllOf;


/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfoldersignerassociationCreateObjectV2Response
 */
export class DefaultObjectEzsignfoldersignerassociationCreateObjectV2Response extends DefaultObject {
   mPayload:Partial<EzsignfoldersignerassociationCreateObjectV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


