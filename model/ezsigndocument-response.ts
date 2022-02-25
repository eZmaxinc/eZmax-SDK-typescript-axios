/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonAudit } from './common-audit';
import { FieldEEzsigndocumentStep } from './field-eezsigndocument-step';

/**
 * An Ezsigndocument Object
 * @export
 * @interface EzsigndocumentResponse
 */
export interface EzsigndocumentResponse {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    'fkiEzsignfolderID': number;
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    'dtEzsigndocumentDuedate': string;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    'fkiLanguageID': number;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    'sEzsigndocumentName': string;
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    'pkiEzsigndocumentID': number;
    /**
     * 
     * @type {FieldEEzsigndocumentStep}
     * @memberof EzsigndocumentResponse
     */
    'eEzsigndocumentStep': FieldEEzsigndocumentStep;
    /**
     * The date and time when the Ezsigndocument was first sent.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    'dtEzsigndocumentFirstsend': string;
    /**
     * The date and time when the Ezsigndocument was sent the last time.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    'dtEzsigndocumentLastsend': string;
    /**
     * The order in which the Ezsigndocument will be presented to the signatory in the Ezsignfolder.
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    'iEzsigndocumentOrder': number;
    /**
     * The number of pages in the Ezsigndocument.
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    'iEzsigndocumentPagetotal': number;
    /**
     * The number of signatures that were signed in the document.
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    'iEzsigndocumentSignaturesigned': number;
    /**
     * The number of total signatures that were requested in the Ezsigndocument.
     * @type {number}
     * @memberof EzsigndocumentResponse
     */
    'iEzsigndocumentSignaturetotal': number;
    /**
     * MD5 Hash of the initial PDF Document before signatures were applied to it.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    'sEzsigndocumentMD5initial': string;
    /**
     * MD5 Hash of the final PDF Document after all signatures were applied to it.
     * @type {string}
     * @memberof EzsigndocumentResponse
     */
    'sEzsigndocumentMD5signed': string;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsigndocumentResponse
     */
    'objAudit': CommonAudit;
}

