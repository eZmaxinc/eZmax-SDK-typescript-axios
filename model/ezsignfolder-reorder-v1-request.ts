/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/reorder
 * @export
 * @interface EzsignfolderReorderV1Request
 */
export interface EzsignfolderReorderV1Request {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfolderReorderV1Request
     */
    'a_pkiEzsigndocumentID': Array<number>;
}

