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
 * An Ezsignbulksend List Element
 * @export
 * @interface EzsignbulksendListElement
 */
export interface EzsignbulksendListElement {
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    'pkiEzsignbulksendID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The description of the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendListElement
     */
    'sEzsignbulksendDescription': string;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsignbulksendListElement
     */
    'sEzsignfoldertypeNameX': string;
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsignbulksendListElement
     */
    'bEzsignbulksendNeedvalidation': boolean;
    /**
     * Whether the Ezsignbulksend is active or not
     * @type {boolean}
     * @memberof EzsignbulksendListElement
     */
    'bEzsignbulksendIsactive': boolean;
    /**
     * The total number of Ezsignbulksendtransmissions in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    'iEzsignbulksendtransmission': number;
    /**
     * The total number of Ezsignfolders in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    'iEzsignfolder': number;
    /**
     * The total number of Ezsigndocuments in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    'iEzsigndocument': number;
    /**
     * The total number of Ezsignsignature in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    'iEzsignsignature': number;
    /**
     * The total number of already signed Ezsignsignature blocks in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    'iEzsignsignatureSigned': number;
}

