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



/**
 * A Ezsignbulksend Object
 * @export
 * @interface EzsignbulksendRequest
 */
export interface EzsignbulksendRequest {
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendRequest
     */
    'pkiEzsignbulksendID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignbulksendRequest
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsignbulksendRequest
     */
    'fkiLanguageID': number;
    /**
     * The description of the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendRequest
     */
    'sEzsignbulksendDescription': string;
    /**
     * Note about the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendRequest
     */
    'tEzsignbulksendNote': string;
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsignbulksendRequest
     */
    'bEzsignbulksendNeedvalidation': boolean;
    /**
     * Whether the Ezsignbulksend is active or not
     * @type {boolean}
     * @memberof EzsignbulksendRequest
     */
    'bEzsignbulksendIsactive': boolean;
}
