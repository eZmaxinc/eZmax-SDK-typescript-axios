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


import { EzsigndocumentResponseCompound } from './ezsigndocument-response-compound';

/**
 * Payload for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage
 * @export
 * @interface EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload
 */
export interface EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigndocumentResponseCompound>}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload
     */
    'a_objEzsigndocument': Array<EzsigndocumentResponseCompound>;
}
