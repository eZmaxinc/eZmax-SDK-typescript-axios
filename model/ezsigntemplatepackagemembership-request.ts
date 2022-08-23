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
 * A Ezsigntemplatepackagemembership Object
 * @export
 * @interface EzsigntemplatepackagemembershipRequest
 */
export interface EzsigntemplatepackagemembershipRequest {
    /**
     * The unique ID of the Ezsigntemplatepackagemembership
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequest
     */
    'pkiEzsigntemplatepackagemembershipID'?: number;
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequest
     */
    'fkiEzsigntemplatepackageID': number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatepackagemembershipRequest
     */
    'fkiEzsigntemplateID': number;
}

