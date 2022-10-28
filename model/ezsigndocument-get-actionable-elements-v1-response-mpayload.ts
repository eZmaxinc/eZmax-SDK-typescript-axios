/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupResponseCompound } from './ezsignformfieldgroup-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureResponseCompound } from './ezsignsignature-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getActionableElements
 * @export
 * @interface EzsigndocumentGetActionableElementsV1ResponseMPayload
 */
export interface EzsigndocumentGetActionableElementsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignsignatureResponseCompound>}
     * @memberof EzsigndocumentGetActionableElementsV1ResponseMPayload
     */
    'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;
    /**
     * 
     * @type {Array<EzsignformfieldgroupResponseCompound>}
     * @memberof EzsigndocumentGetActionableElementsV1ResponseMPayload
     */
    'a_objEzsignformfieldgroup': Array<EzsignformfieldgroupResponseCompound>;
}
/**
 * A EzsigndocumentGetActionableElementsV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetActionableElementsV1ResponseMPayload
 */
export class DefaultObjectEzsigndocumentGetActionableElementsV1ResponseMPayload extends DefaultObject {
   a_objEzsignsignature:Array<EzsignsignatureResponseCompound> = []
   a_objEzsignformfieldgroup:Array<EzsignformfieldgroupResponseCompound> = []
}


