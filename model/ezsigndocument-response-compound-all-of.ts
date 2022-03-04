/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.6
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CustomEzsignfoldersignerassociationstatusResponse } from './custom-ezsignfoldersignerassociationstatus-response';

/**
 * 
 * @export
 * @interface EzsigndocumentResponseCompoundAllOf
 */
export interface EzsigndocumentResponseCompoundAllOf {
    /**
     * The total number of steps in the form filling phase
     * @type {number}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'iEzsigndocumentStepformtotal': number;
    /**
     * The current step in the form filling phase
     * @type {number}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'iEzsigndocumentStepformcurrent': number;
    /**
     * The total number of steps in the signature filling phase
     * @type {number}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'iEzsigndocumentStepsignaturetotal': number;
    /**
     * The current step in the signature phase
     * @type {number}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'iEzsigndocumentStepsignatureCurrent': number;
    /**
     * 
     * @type {Array<CustomEzsignfoldersignerassociationstatusResponse>}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'a_objEzsignfoldersignerassociationstatus': Array<CustomEzsignfoldersignerassociationstatusResponse>;
}

