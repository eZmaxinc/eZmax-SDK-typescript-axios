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


import { EzsignfoldersignerassociationResponseCompoundUser } from './ezsignfoldersignerassociation-response-compound-user';
import { EzsignsignerResponseCompound } from './ezsignsigner-response-compound';

/**
 * 
 * @export
 * @interface EzsignfoldersignerassociationResponseCompoundAllOf
 */
export interface EzsignfoldersignerassociationResponseCompoundAllOf {
    /**
     * 
     * @type {EzsignfoldersignerassociationResponseCompoundUser}
     * @memberof EzsignfoldersignerassociationResponseCompoundAllOf
     */
    'objUser'?: EzsignfoldersignerassociationResponseCompoundUser;
    /**
     * 
     * @type {EzsignsignerResponseCompound}
     * @memberof EzsignfoldersignerassociationResponseCompoundAllOf
     */
    'objEzsignsigner'?: EzsignsignerResponseCompound;
}

