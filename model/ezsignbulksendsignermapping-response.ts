/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezsignbulksendsignermapping Object
 * @export
 * @interface EzsignbulksendsignermappingResponse
 */
export interface EzsignbulksendsignermappingResponse {
    /**
     * The unique ID of the Ezsignbulksendsignermapping
     * @type {number}
     * @memberof EzsignbulksendsignermappingResponse
     */
    'pkiEzsignbulksendsignermappingID': number;
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendsignermappingResponse
     */
    'fkiEzsignbulksendID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignbulksendsignermappingResponse
     */
    'fkiUserID'?: number;
    /**
     * The description of the Ezsignbulksendsignermapping
     * @type {string}
     * @memberof EzsignbulksendsignermappingResponse
     */
    'sEzsignbulksendsignermappingDescription': string;
}

