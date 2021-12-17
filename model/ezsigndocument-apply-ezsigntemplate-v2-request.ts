/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.3
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for the /2/object/ezsigndocument/{pkiEzsigndocumentID}/applyezsigntemplate API Request
 * @export
 * @interface EzsigndocumentApplyEzsigntemplateV2Request
 */
export interface EzsigndocumentApplyEzsigntemplateV2Request {
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Request
     */
    'fkiEzsigntemplateID': number;
    /**
     * 
     * @type {Array<string>}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Request
     */
    'a_sEzsigntemplatesigner': Array<string>;
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Request
     */
    'a_pkiEzsignfoldersignerassociationID': Array<number>;
}

