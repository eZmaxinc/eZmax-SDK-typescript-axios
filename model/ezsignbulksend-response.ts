/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonAudit } from './common-audit';

/**
 * An Ezsignbulksend Object
 * @export
 * @interface EzsignbulksendResponse
 */
export interface EzsignbulksendResponse {
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendResponse
     */
    'pkiEzsignbulksendID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignbulksendResponse
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsignbulksendResponse
     */
    'fkiLanguageID': number;
    /**
     * The description of the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendResponse
     */
    'sEzsignbulksendDescription': string;
    /**
     * Note about the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendResponse
     */
    'tEzsignbulksendNote': string;
    /**
     * Whether the Ezsignbulksend is active or not
     * @type {boolean}
     * @memberof EzsignbulksendResponse
     */
    'bEzsignbulksendIsactive': boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsignbulksendResponse
     */
    'objAudit': CommonAudit;
}

