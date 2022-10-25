/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';

import { DefaultObject } from '../base'

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
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof EzsignbulksendResponse
     */
    'sLanguageNameX': string;
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsignbulksendResponse
     */
    'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsignbulksendResponse
     */
    'sEzsignfoldertypeNameX': string;
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
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsignbulksendResponse
     */
    'bEzsignbulksendNeedvalidation': boolean;
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
/**
 * A EzsignbulksendResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendResponse
 */
export class DefaultObjectEzsignbulksendResponse extends DefaultObject {
   pkiEzsignbulksendID:number = 0
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   sEzsignfoldertypeNameX:string = ''
   sEzsignbulksendDescription:string = ''
   tEzsignbulksendNote:string = ''
   bEzsignbulksendNeedvalidation:boolean = false
   bEzsignbulksendIsactive:boolean = false
   objAudit:Partial<CommonAudit> = {}
}


