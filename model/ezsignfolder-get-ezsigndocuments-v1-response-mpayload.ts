/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.5
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigndocumentResponseCompound } from './ezsigndocument-response-compound';

/**
 * Payload for the /1/object/ezsignfolder/{pkiEzsignfolder}/getEzsigndocuments API Request
 * @export
 * @interface EzsignfolderGetEzsigndocumentsV1ResponseMPayload
 */
export interface EzsignfolderGetEzsigndocumentsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigndocumentResponseCompound>}
     * @memberof EzsignfolderGetEzsigndocumentsV1ResponseMPayload
     */
    'a_objEzsigndocument': Array<EzsigndocumentResponseCompound>;
}

