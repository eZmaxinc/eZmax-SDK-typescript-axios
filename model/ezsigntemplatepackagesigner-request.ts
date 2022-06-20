/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezsigntemplatepackagesigner Object
 * @export
 * @interface EzsigntemplatepackagesignerRequest
 */
export interface EzsigntemplatepackagesignerRequest {
    /**
     * The unique ID of the Ezsigntemplatepackagesigner
     * @type {number}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    'pkiEzsigntemplatepackagesignerID'?: number;
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    'fkiEzsigntemplatepackageID': number;
    /**
     * The description of the Ezsigntemplatepackagesigner
     * @type {string}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    'sEzsigntemplatepackagesignerDescription': string;
}

