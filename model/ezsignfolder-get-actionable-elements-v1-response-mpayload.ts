/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsignformfieldgroupResponseCompound } from './ezsignformfieldgroup-response-compound';
import { EzsignsignatureResponseCompound } from './ezsignsignature-response-compound';

/**
 * Payload for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getActionableElements
 * @export
 * @interface EzsignfolderGetActionableElementsV1ResponseMPayload
 */
export interface EzsignfolderGetActionableElementsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignsignatureResponseCompound>}
     * @memberof EzsignfolderGetActionableElementsV1ResponseMPayload
     */
    'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;
    /**
     * 
     * @type {Array<EzsignformfieldgroupResponseCompound>}
     * @memberof EzsignfolderGetActionableElementsV1ResponseMPayload
     */
    'a_objEzsignformfieldgroup': Array<EzsignformfieldgroupResponseCompound>;
}

